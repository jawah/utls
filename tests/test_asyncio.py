from __future__ import annotations

import asyncio
import ssl

import pytest
import trustme

import utls


async def _pump_until(sslobj, op, reader, writer, inc, out):
    """Repeatedly invoke ``op()`` (a 0-arg callable on ``sslobj``), shuttling
    ciphertext between ``inc``/``out`` and the underlying asyncio
    reader/writer until ``op`` returns without raising
    ``SSLWantReadError`` / ``SSLWantWriteError``. Returns ``op``'s result.
    """
    while True:
        try:
            return op()
        except utls.SSLWantReadError:
            if out.pending:
                writer.write(out.read(-1))
                await writer.drain()
            chunk = await reader.read(4096)
            if not chunk:
                inc.write_eof()
                raise
            inc.write(chunk)
        except utls.SSLWantWriteError:
            writer.write(out.read(-1))
            await writer.drain()


@pytest.mark.asyncio
async def test_memorybio_handshake_against_in_process_server():
    ca = trustme.CA()
    server_cert = ca.issue_cert("127.0.0.1")

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_ctx)

    client_ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = True
    client_ctx.verify_mode = utls.CERT_REQUIRED
    # trustme 1.2+ type-checks ``configure_trust`` against ``ssl.SSLContext``
    # / ``OpenSSL.SSL.Context``; utls' context is neither, so we feed the
    # PEM directly. Same end result.
    client_ctx.load_verify_locations(cadata=ca.cert_pem.bytes().decode("ascii"))

    async def server_handler(reader, writer):
        try:
            data = await reader.read(5)
            if data:
                writer.write(b"PONG:" + data)
                await writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass

    srv = await asyncio.start_server(
        server_handler, "127.0.0.1", 0, ssl=server_ctx
    )
    port = srv.sockets[0].getsockname()[1]

    async with srv:
        reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=None)
        inc, out = utls.MemoryBIO(), utls.MemoryBIO()
        sslobj = client_ctx.wrap_bio(inc, out, server_hostname="127.0.0.1")
        try:
            # Handshake.
            await _pump_until(sslobj, sslobj.do_handshake, reader, writer, inc, out)

            # asyncio _get_extra_info parity: these accessors must work
            # post-handshake so SSLProtocol can populate transport.get_extra_info().
            assert sslobj.version().startswith("TLSv1.")
            cipher = sslobj.cipher()
            assert cipher is not None and len(cipher) == 3
            # ALPN wasn't negotiated (neither side offered) -> None.
            assert sslobj.selected_alpn_protocol() is None
            cert = sslobj.getpeercert()
            assert isinstance(cert, dict) and cert  # IP-SAN cert verified
            # BoringSSL never negotiates TLS compression -> always None.
            assert sslobj.compression() is None

            # Application data round-trip.
            await _pump_until(
                sslobj, lambda: sslobj.write(b"PING\n"), reader, writer, inc, out
            )
            if out.pending:
                writer.write(out.read(-1))
                await writer.drain()
            reply = await _pump_until(
                sslobj, lambda: sslobj.read(9), reader, writer, inc, out
            )
            assert reply == b"PONG:PING"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass


@pytest.mark.asyncio
async def test_loop_create_connection_populates_extra_info():
    """End-to-end asyncio integration via ``loop.create_connection(ssl=ctx)``.

    Proves an :class:`utls.SSLContext` plugs into asyncio's
    :class:`SSLProtocol` and that the resulting transport exposes the four
    keys :meth:`asyncio.BaseTransport.get_extra_info` populates from the
    SSL object: ``ssl_object`` / ``compression`` / ``cipher`` / ``peercert``.
    This is the contract third-party HTTP-over-asyncio stacks
    (aiohttp, httpcore, urllib3.future) read from.
    """
    ca = trustme.CA()
    server_cert = ca.issue_cert("127.0.0.1")
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_ctx)

    client_ctx = utls.create_default_context()
    client_ctx.load_verify_locations(cadata=ca.cert_pem.bytes().decode("ascii"))

    async def server_handler(reader, writer):
        try:
            await reader.read(1)
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass

    srv = await asyncio.start_server(server_handler, "127.0.0.1", 0, ssl=server_ctx)
    port = srv.sockets[0].getsockname()[1]
    async with srv:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=client_ctx, server_hostname="127.0.0.1"
        )
        try:
            sslobj = writer.get_extra_info("ssl_object")
            assert isinstance(sslobj, utls.SSLObject)
            assert sslobj.version().startswith("TLSv1.")

            cipher = writer.get_extra_info("cipher")
            assert cipher is not None and len(cipher) == 3
            assert cipher == sslobj.cipher()

            # compression must be None (BoringSSL never enables it).
            assert writer.get_extra_info("compression") is None

            peercert = writer.get_extra_info("peercert")
            assert isinstance(peercert, dict)
            assert "subjectAltName" in peercert
            assert ("IP Address", "127.0.0.1") in peercert["subjectAltName"]

            # sslcontext key is the SSLContext we passed in.
            assert writer.get_extra_info("sslcontext") is client_ctx
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass

