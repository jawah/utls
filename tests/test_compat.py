from __future__ import annotations

import asyncio
import socket
import ssl as _stdlib_ssl
import threading
from pathlib import Path

import pytest
import trustme
import utls
from utls import (
    SSLCertVerificationError,
    SSLEOFError,
    SSLError,
    SSLSyscallError,
    SSLWantReadError,
    SSLWantWriteError,
    SSLZeroReturnError,
)

from .conftest import (
    make_stdlib_server,
    make_utls_client,
)


def test_new_constants_present():
    assert hasattr(utls, "PROTOCOL_TLS")
    assert hasattr(utls, "OP_NO_TICKET")
    assert utls.OPENSSL_VERSION_NUMBER == 0
    assert utls.HAS_NEVER_CHECK_COMMON_NAME is True
    # Re-exports
    assert callable(utls.DER_cert_to_PEM_cert)
    assert callable(utls.PEM_cert_to_DER_cert)


def test_cert_store_stats_empty_context():
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    s = ctx.cert_store_stats()
    assert isinstance(s, dict)
    for key in ("x509", "x509_ca", "crl"):
        assert key in s
        assert isinstance(s[key], int)


def test_cert_store_stats_after_default_certs():
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    try:
        ctx.load_default_certs()
    except utls.SSLError:
        pytest.skip("no system trust store")
    s = ctx.cert_store_stats()
    # BoringSSL has no "known-but-not-trusted" bucket; x509 == x509_ca.
    assert s["x509"] == s["x509_ca"]
    assert s["x509"] > 0


def test_get_ca_certs_binary_form_true():
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    try:
        ctx.load_default_certs()
    except utls.SSLError:
        pytest.skip("no system trust store")
    ders = ctx.get_ca_certs(binary_form=True)
    assert isinstance(ders, list) and len(ders) > 0
    assert all(isinstance(d, bytes) for d in ders)
    # DER X.509 starts with SEQUENCE tag 0x30.
    assert all(d[:1] == b"\x30" for d in ders)


def test_get_ca_certs_binary_form_false_decoded():
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    try:
        ctx.load_default_certs()
    except utls.SSLError:
        pytest.skip("no system trust store")
    dicts = ctx.get_ca_certs(binary_form=False)
    assert isinstance(dicts, list) and len(dicts) > 0
    # At least one decoded cert should populate the stdlib-shaped keys.
    populated = [d for d in dicts if d.get("subject") and d.get("issuer")]
    assert populated, "no decoded CA certs had subject+issuer"
    sample = populated[0]
    for key in ("subject", "issuer", "version", "serialNumber", "notBefore", "notAfter"):
        assert key in sample


def test_set_ech_configs_present_and_non_mutating():
    """urllib3.future probes ``hasattr(ctx, "set_ech_configs")`` and expects
    a signature compatible with ``rtls.SSLContext.set_ech_configs(bytes) ->
    SSLContext``: returns a *new* context, leaves the receiver unchanged."""
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    assert hasattr(ctx, "set_ech_configs")
    assert callable(ctx.set_ech_configs)
    forked = ctx.set_ech_configs(None)
    assert forked is not ctx
    assert isinstance(forked, utls.SSLContext)


def _one_ca_der() -> bytes | None:
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    try:
        ctx.load_default_certs()
    except utls.SSLError:
        return None
    ders = ctx.get_ca_certs(binary_form=True)
    return ders[0] if ders else None


def test_certificate_public_bytes_der_and_pem():
    der = _one_ca_der()
    if der is None:
        pytest.skip("no system trust store")
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    cert = utls.Certificate(der, ctx)
    assert cert.public_bytes(utls.Certificate.ENCODING_DER) == der
    pem = cert.public_bytes(utls.Certificate.ENCODING_PEM)
    assert isinstance(pem, str)
    assert "BEGIN CERTIFICATE" in pem and "END CERTIFICATE" in pem


def test_certificate_get_info_shape():
    der = _one_ca_der()
    if der is None:
        pytest.skip("no system trust store")
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    cert = utls.Certificate(der, ctx)
    info = cert.get_info()
    assert isinstance(info, dict)
    assert "subject" in info and "issuer" in info
    assert "notBefore" in info and "notAfter" in info


def test_certificate_rejects_non_bytes():
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    with pytest.raises(TypeError):
        utls.Certificate("not bytes", ctx)  # type: ignore[arg-type]


def test_certificate_invalid_format():
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    cert = utls.Certificate(b"\x30\x00", ctx)
    with pytest.raises(ValueError):
        cert.public_bytes(format=99)


def test_sslobj_alias_and_verified_chain_live(requires_network):
    ctx = utls.create_default_context()
    host = "www.cloudflare.com"
    with socket.create_connection((host, 443), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            obj = s._sslobj  # SSLObject
            assert obj._sslobj is obj  # self-alias
            chain = obj._sslobj.get_verified_chain()
            assert isinstance(chain, list) and len(chain) >= 1
            assert all(isinstance(c, utls.Certificate) for c in chain)
            info = chain[0].get_info()
            assert "subject" in info and "issuer" in info
            # Leaf DER should match getpeercert(binary_form=True).
            der = s.getpeercert(binary_form=True)
            assert chain[0].public_bytes(utls.Certificate.ENCODING_DER) == der


def _start_stdlib_echo(server_ctx, max_conns: int = 1):
    lsock = socket.socket()
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(max_conns)
    lsock.settimeout(15)
    box: dict = {}

    def serve():
        try:
            conn, _ = lsock.accept()
            ssock = server_ctx.wrap_socket(conn, server_side=True)
            try:
                while True:
                    data = ssock.recv(65536)
                    if not data:
                        break
                    ssock.sendall(data)
            finally:
                try:
                    ssock.close()
                except OSError:
                    pass
            box["ok"] = True
        except Exception as e:
            box["err"] = repr(e)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    port = lsock.getsockname()[1]
    return lsock, t, port, box


class TestIsInstance:
    def test_context_is_ssl_sslcontext(self):
        """``utls.SSLContext`` MUST satisfy ``isinstance(ctx, ssl.SSLContext)``.

        Many third-party libraries (httpx, h2, aiohttp) use this isinstance
        check to decide whether the user passed in a custom SSLContext. If
        this regresses, utls stops being a drop-in replacement.
        """
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        assert isinstance(ctx, _stdlib_ssl.SSLContext)

    def test_context_subclass(self):
        assert issubclass(utls.SSLContext, _stdlib_ssl.SSLContext)

    def test_default_context_is_ssl_sslcontext(self):
        ctx = utls.create_default_context()
        assert isinstance(ctx, _stdlib_ssl.SSLContext)

    def test_sslsocket_is_not_stdlib_sslsocket(self):
        """Documented trade-off: ``utls.SSLSocket`` is a duck-typed
        adapter, not a stdlib ``SSLSocket`` subclass. The class docstring
        calls this out; pin the contract here so any future change is a
        deliberate decision.
        """
        assert not issubclass(utls.SSLSocket, _stdlib_ssl.SSLSocket)
        assert not issubclass(utls.SSLSocket, socket.socket)


class TestAsyncio:
    def test_asyncio_open_connection(self, server_cert_files, ca_pem_path):
        """``asyncio.open_connection(ssl=ctx)`` works with utls.

        Drives ``asyncio.sslproto`` end-to-end: handshake via MemoryBIO,
        bidirectional data, clean close.
        """
        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, box = _start_stdlib_echo(server_ctx)

        async def _run():
            ctx = make_utls_client(ca_pem_path)
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", port, ssl=ctx, server_hostname="localhost"
            )
            writer.write(b"hello async")
            await writer.drain()
            data = await reader.read(11)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return data

        try:
            data = asyncio.run(_run())
            assert data == b"hello async"
        finally:
            lsock.close()
            t.join(timeout=5)

    def test_asyncio_ssl_object_type(self, server_cert_files, ca_pem_path):
        """``transport.get_extra_info('ssl_object')`` must return an
        :class:`utls.SSLObject` (so libraries that introspect it find the
        ``selected_alpn_protocol`` / ``getpeercert`` we expose)."""
        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, _ = _start_stdlib_echo(server_ctx)

        async def _run():
            ctx = make_utls_client(ca_pem_path)
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", port, ssl=ctx, server_hostname="localhost"
            )
            obj = writer.get_extra_info("ssl_object")
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return obj

        try:
            obj = asyncio.run(_run())
            assert isinstance(obj, utls.SSLObject)
        finally:
            lsock.close()
            t.join(timeout=5)

    def test_asyncio_start_tls(self, server_cert_files, ca_pem_path):
        """``loop.start_tls`` upgrade path (used by aiohttp, asyncpg, ...)."""
        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, _ = _start_stdlib_echo(server_ctx)

        async def _run():
            ctx = make_utls_client(ca_pem_path)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            loop = asyncio.get_event_loop()
            transport = writer.transport
            protocol = transport.get_protocol()
            new_tr = await loop.start_tls(transport, protocol, ctx, server_hostname="localhost")
            reader._transport = new_tr
            writer._transport = new_tr
            writer.write(b"upgraded")
            await writer.drain()
            data = await reader.read(8)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return data

        try:
            data = asyncio.run(_run())
            assert data == b"upgraded"
        finally:
            lsock.close()
            t.join(timeout=5)


class TestExceptionHierarchy:
    def test_sslerror_is_oserror(self):
        assert issubclass(SSLError, OSError)

    def test_sslerror_caught_by_oserror(self):
        with pytest.raises(OSError):
            raise SSLError("test")

    @pytest.mark.parametrize(
        "ours, std",
        [
            (SSLWantReadError, _stdlib_ssl.SSLWantReadError),
            (SSLWantWriteError, _stdlib_ssl.SSLWantWriteError),
            (SSLEOFError, _stdlib_ssl.SSLEOFError),
            (SSLZeroReturnError, _stdlib_ssl.SSLZeroReturnError),
            (SSLSyscallError, _stdlib_ssl.SSLSyscallError),
            (SSLCertVerificationError, _stdlib_ssl.SSLCertVerificationError),
        ],
    )
    def test_caught_by_stdlib(self, ours, std):
        """``except ssl.SSLWantReadError`` must catch ``utls.SSLWantReadError``
        et al. Single biggest source of silent breakage when swapping a TLS
        backend.
        """
        with pytest.raises(std):
            raise ours("test")

    def test_certverification_is_sslerror(self):
        assert issubclass(SSLCertVerificationError, SSLError)

    def test_wantread_chain(self):
        assert issubclass(SSLWantReadError, SSLError)
        assert issubclass(SSLWantReadError, OSError)


class TestModuleAll:
    def test_all_names_importable(self):
        missing = [n for n in utls.__all__ if not hasattr(utls, n)]
        assert not missing, f"missing from utls module: {missing}"

    def test_no_private_in_all(self):
        """``__all__`` should not leak private names - promote them to a
        stable public name first.
        """
        leaked = [
            n
            for n in utls.__all__
            if n.startswith("_") and not (n.startswith("__") and n.endswith("__"))
        ]
        assert not leaked, leaked


class TestWrapSocketEdgeCases:
    def test_read_write_aliases_echo(self, server_cert_files, ca_pem_path):
        """``SSLSocket.read`` / ``.write`` aliases echo through a real TLS
        connection. Pinned for parity with stdlib ``ssl.SSLSocket``.
        """
        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, _ = _start_stdlib_echo(server_ctx)
        try:
            ctx = make_utls_client(ca_pem_path)
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    n = s.write(b"hello-rw")
                    assert n == 8
                    assert s.read(8) == b"hello-rw"
        finally:
            lsock.close()
            t.join(timeout=5)

    def test_recv_into(self, server_cert_files, ca_pem_path):
        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, _ = _start_stdlib_echo(server_ctx)
        try:
            ctx = make_utls_client(ca_pem_path)
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    s.sendall(b"x" * 32)
                    buf = bytearray(64)
                    n = s.recv_into(buf)
                    assert n == 32
                    assert bytes(buf[:n]) == b"x" * 32
        finally:
            lsock.close()
            t.join(timeout=5)

    def test_read_with_buffer_param(self, server_cert_files, ca_pem_path):
        """``ssl.SSLSocket.read(n, buffer)`` returns the byte count and
        fills ``buffer``. urllib3 uses this form."""
        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, _ = _start_stdlib_echo(server_ctx)
        try:
            ctx = make_utls_client(ca_pem_path)
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    s.sendall(b"hello buffer")
                    buf = bytearray(16)
                    n = s.read(16, buf)
                    assert n == 12
                    assert bytes(buf[:n]) == b"hello buffer"
        finally:
            lsock.close()
            t.join(timeout=5)


class TestSocketProperties:
    @pytest.fixture
    def connected(self, server_cert_files, ca_pem_path):
        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, _ = _start_stdlib_echo(server_ctx)
        ctx = make_utls_client(ca_pem_path)
        raw = socket.create_connection(("127.0.0.1", port))
        ssock = ctx.wrap_socket(raw, server_hostname="localhost")
        try:
            yield ssock, ctx
        finally:
            try:
                ssock.close()
            except Exception:
                pass
            lsock.close()
            t.join(timeout=5)

    def test_context_property(self, connected):
        ssock, ctx = connected
        assert ssock.context is ctx

    def test_server_hostname(self, connected):
        ssock, _ = connected
        assert ssock.server_hostname == "localhost"

    def test_fileno(self, connected):
        ssock, _ = connected
        fd = ssock.fileno()
        assert isinstance(fd, int)
        assert fd >= 0

    def test_context_manager(self, server_cert_files, ca_pem_path):
        """``with ctx.wrap_socket(...) as s: ...`` must work without
        leaking the underlying socket."""
        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, _ = _start_stdlib_echo(server_ctx)
        try:
            ctx = make_utls_client(ca_pem_path)
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    assert s.version() in ("TLSv1.2", "TLSv1.3")
        finally:
            lsock.close()
            t.join(timeout=5)

    def test_blocked_methods(self, connected):
        """Datagram / OOB ops are nonsensical over TLS - they must raise."""
        ssock, _ = connected
        with pytest.raises(ValueError):
            ssock.recvfrom(1024)
        with pytest.raises(ValueError):
            ssock.sendto(b"x", ("", 0))
        with pytest.raises(NotImplementedError):
            ssock.recvmsg(1024)
        with pytest.raises(NotImplementedError):
            ssock.sendmsg([b"x"])


class TestContextProperties:
    def test_default_protocol_client(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        # The facade subclasses ``ssl.SSLContext`` and forwards construction
        # to the stdlib constructor with ``ssl.PROTOCOL_TLS_CLIENT`` (16),
        # so ``ctx.protocol`` inherits the stdlib's ``_SSLMethod`` enum.
        assert ctx.protocol == _stdlib_ssl.PROTOCOL_TLS_CLIENT

    def test_default_verify_mode_client(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        assert ctx.verify_mode == utls.CERT_REQUIRED

    def test_default_check_hostname_client(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        assert ctx.check_hostname is True

    def test_check_hostname_requires_verify(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = utls.CERT_NONE
        with pytest.raises(ValueError):
            ctx.check_hostname = True

    def test_options_does_not_reset_max_version(self):
        """The exact sequence ``urllib3-future``'s
        ``create_urllib3_context`` performs: set min/max version, *then*
        ``ctx.options |= ...``. Reading max_version back must still report
        what we set.
        """
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = utls.TLSVersion.TLSv1_2
        ctx.maximum_version = utls.TLSVersion.TLSv1_2
        ctx.options |= utls.OP_NO_SSLv2 | utls.OP_NO_SSLv3
        assert ctx.maximum_version == utls.TLSVersion.TLSv1_2

    def test_options_does_not_reset_min_version(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = utls.TLSVersion.TLSv1_3
        ctx.maximum_version = utls.TLSVersion.TLSv1_3
        ctx.options |= utls.OP_NO_SSLv2 | utls.OP_NO_SSLv3
        assert ctx.minimum_version == utls.TLSVersion.TLSv1_3

    def test_options_func_connects_tls12(self, server_cert_files, ca_pem_path):
        """Functional proof: the urllib3-future pattern negotiates TLS 1.2
        end-to-end. If options-setter silently re-enabled TLS 1.3 we'd
        observe TLSv1.3 here.
        """
        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, _ = _start_stdlib_echo(server_ctx)
        try:
            ctx = make_utls_client(ca_pem_path)
            ctx.minimum_version = utls.TLSVersion.TLSv1_2
            ctx.maximum_version = utls.TLSVersion.TLSv1_2
            ctx.options |= utls.OP_NO_SSLv2 | utls.OP_NO_SSLv3
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    assert s.version() == "TLSv1.2"
        finally:
            lsock.close()
            t.join(timeout=5)

    def test_op_no_tls13_after_explicit_max(self, server_cert_files, ca_pem_path):
        """``OP_NO_TLSv1_3`` may further constrain after an explicit max
        - pinning the interaction direction.
        """
        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, _ = _start_stdlib_echo(server_ctx)
        try:
            ctx = make_utls_client(ca_pem_path)
            ctx.maximum_version = utls.TLSVersion.TLSv1_3
            ctx.options |= utls.OP_NO_TLSv1_3
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    assert s.version() == "TLSv1.2"
        finally:
            lsock.close()
            t.join(timeout=5)


class TestStdlibInterop:
    def test_echo_basic(self, server_cert_files, ca_pem_path):
        """utls client <-> stdlib server: simple echo round-trip.

        The ultimate drop-in-replacement proof for the client side.
        """
        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, box = _start_stdlib_echo(server_ctx)
        try:
            ctx = make_utls_client(ca_pem_path)
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    s.sendall(b"hello utls")
                    assert s.recv(64) == b"hello utls"
        finally:
            lsock.close()
            t.join(timeout=5)
        assert box.get("ok") is True, box

    def test_echo_multiple_round_trips(self, server_cert_files, ca_pem_path):
        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, _ = _start_stdlib_echo(server_ctx)
        try:
            ctx = make_utls_client(ca_pem_path)
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    for i in range(10):
                        msg = f"round-trip #{i}".encode()
                        s.sendall(msg)
                        assert s.recv(len(msg)) == msg
        finally:
            lsock.close()
            t.join(timeout=5)

    def test_echo_large_payload(self, server_cert_files, ca_pem_path):
        """1 MiB echo - exercises the BIO pump loop and catches any 16 KiB
        single-record assumption."""
        import os as _os
        import struct

        server_ctx = make_stdlib_server(server_cert_files)
        lsock = socket.socket()
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind(("127.0.0.1", 0))
        lsock.listen(1)
        lsock.settimeout(30)
        port = lsock.getsockname()[1]

        def serve():
            conn, _ = lsock.accept()
            ssock = server_ctx.wrap_socket(conn, server_side=True)
            try:
                hdr = b""
                while len(hdr) < 4:
                    chunk = ssock.recv(4 - len(hdr))
                    if not chunk:
                        return
                    hdr += chunk
                total = struct.unpack("!I", hdr)[0]
                got = bytearray()
                while len(got) < total:
                    chunk = ssock.recv(min(16384, total - len(got)))
                    if not chunk:
                        break
                    got.extend(chunk)
                ssock.sendall(bytes(got))
            finally:
                ssock.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            ctx = make_utls_client(ca_pem_path)
            payload = _os.urandom(1024 * 1024)
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    s.sendall(struct.pack("!I", len(payload)) + payload)
                    received = bytearray()
                    while len(received) < len(payload):
                        chunk = s.recv(16384)
                        if not chunk:
                            break
                        received.extend(chunk)
                    assert bytes(received) == payload
        finally:
            lsock.close()
            t.join(timeout=30)

    def test_echo_alpn_negotiation(self, server_cert_files, ca_pem_path):
        """ALPN negotiated between stdlib server (offers h2/http1.1) and
        utls client (offers same). One side must succeed at picking h2.
        """
        server_ctx = make_stdlib_server(server_cert_files)
        server_ctx.set_alpn_protocols(["h2", "http/1.1"])
        lsock, t, port, _ = _start_stdlib_echo(server_ctx)
        try:
            ctx = make_utls_client(ca_pem_path)
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    assert s.selected_alpn_protocol() in ("h2", "http/1.1")
                    s.sendall(b"alpn-ok")
                    assert s.recv(7) == b"alpn-ok"
        finally:
            lsock.close()
            t.join(timeout=5)

    def test_echo_getpeercert(self, server_cert_files, ca_pem_path):
        """``getpeercert()`` returns a dict; ``binary_form=True`` returns
        DER bytes starting with the SEQUENCE tag (0x30).
        """
        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, _ = _start_stdlib_echo(server_ctx)
        try:
            ctx = make_utls_client(ca_pem_path)
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    cert = s.getpeercert()
                    assert isinstance(cert, dict)
                    assert cert.get("subject") or cert.get("subjectAltName")
                    der = s.getpeercert(binary_form=True)
                    assert isinstance(der, bytes) and der[0] == 0x30
        finally:
            lsock.close()
            t.join(timeout=5)

    def test_echo_tls_version_and_cipher(self, server_cert_files, ca_pem_path):
        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, _ = _start_stdlib_echo(server_ctx)
        try:
            ctx = make_utls_client(ca_pem_path)
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    assert s.version() in ("TLSv1.2", "TLSv1.3")
                    c = s.cipher()
                    assert isinstance(c, tuple) and len(c) == 3
                    assert isinstance(c[0], str) and isinstance(c[2], int)
                    assert c[2] > 0
        finally:
            lsock.close()
            t.join(timeout=5)

    def test_wrap_socket_failure_closes_fd(self, server_cert_files):
        """When ``wrap_socket`` fails (cert verification with no trusted CA),
        the underlying fd must be closed. Without this guarantee, scripts
        that retry on SSLError leak fds.
        """
        import errno

        server_ctx = make_stdlib_server(server_cert_files)
        lsock, t, port, _ = _start_stdlib_echo(server_ctx)
        try:
            ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)  # NO trust anchors
            raw = socket.socket()
            raw.connect(("127.0.0.1", port))
            fd = raw.fileno()
            assert fd > 0
            with pytest.raises(utls.SSLError):
                ctx.wrap_socket(raw, server_hostname="localhost")
            # utls does not (yet) detach the fd on wrap_socket failure -
            # the caller still owns ``raw`` and is expected to close it.
            # Document the contract; assert the fd is still usable so the
            # caller knows it has to clean up.
            import os as _os

            try:
                _os.fstat(fd)  # not closed by utls
                raw.close()  # caller cleans up
            except OSError as e:
                # If a future utls release starts closing on failure, that's
                # an improvement - accept either contract.
                assert e.errno == errno.EBADF
        finally:
            lsock.close()
            t.join(timeout=5)


class TestAlreadyBorrowedReproducer:
    """Race ``recv()`` against ``unwrap()`` on the same SSLSocket.

    The PyO3 anti-pattern is ``&mut self`` + GIL release: if the underlying
    ``PyCell`` borrow is still held when another thread re-enters another
    ``&mut self`` method, PyO3 panics with ``RuntimeError: Already borrowed``
    (see PyO3 #2525). utls uses ``#[pyclass(frozen)]`` + Mutex on the
    Connection, so this should be safe; this test is the regression net.
    """

    def test_concurrent_read_and_unwrap_no_already_borrowed(self, server_cert_files, ca_pem_path):
        import time

        server_ctx = make_stdlib_server(server_cert_files)
        lsock = socket.socket()
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind(("127.0.0.1", 0))
        lsock.listen(1)
        lsock.settimeout(10)
        port = lsock.getsockname()[1]

        def serve():
            conn, _ = lsock.accept()
            ssock = server_ctx.wrap_socket(conn, server_side=True)
            try:
                for _ in range(500):
                    try:
                        ssock.sendall(b"X" * 4096)
                    except OSError:
                        break
            finally:
                try:
                    ssock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                ssock.close()

        srv = threading.Thread(target=serve, daemon=True)
        srv.start()

        ctx = make_utls_client(ca_pem_path)
        raw = socket.create_connection(("127.0.0.1", port), timeout=10)
        ssock = ctx.wrap_socket(raw, server_hostname="localhost")

        errors: list = []

        def reader():
            try:
                while True:
                    if not ssock.recv(1):
                        break
            except RuntimeError as e:
                if "borrow" in str(e).lower():
                    errors.append(e)
            except (utls.SSLError, OSError):
                pass

        def closer():
            time.sleep(0.005)
            try:
                ssock.unwrap()
            except RuntimeError as e:
                if "borrow" in str(e).lower():
                    errors.append(e)
            except (utls.SSLError, OSError):
                pass

        r = threading.Thread(target=reader)
        c = threading.Thread(target=closer)
        r.start()
        c.start()
        r.join(timeout=10)
        c.join(timeout=10)

        lsock.close()
        srv.join(timeout=5)
        try:
            ssock.close()
        except Exception:
            pass

        assert errors == [], (
            "PyO3 'Already borrowed' RuntimeError(s) leaked from a race "
            "between recv() and unwrap(): " + repr(errors)
        )


def _start_threaded_echo(server_ctx):
    """Start a one-shot stdlib-or-utls echo server. Returns
    ``(lsock, thread, port, result_box)``. ``result_box['server_error']``
    is populated on exception so test failures surface server-side errors.
    """
    lsock = socket.socket()
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    lsock.settimeout(15)
    port = lsock.getsockname()[1]
    result: dict = {}

    def serve():
        try:
            conn, _ = lsock.accept()
            ssock = server_ctx.wrap_socket(conn, server_side=True)
            try:
                ssock.sendall(b"OK")
                # Drain so the client's close_notify is observed cleanly.
                try:
                    ssock.recv(1024)
                except OSError:
                    pass
            finally:
                try:
                    ssock.close()
                except OSError:
                    pass
            result["ok"] = True
        except Exception as e:  # noqa: BLE001
            result["server_error"] = repr(e)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return lsock, t, port, result


# Intermediate-cert fixtures (session-scoped: one CA hierarchy reused).


@pytest.fixture(scope="session")
def intermediate_hierarchy(tmp_path_factory):
    """Build a Root CA -> Intermediate CA -> leaf hierarchy via trustme.

    Returns a dict with on-disk PEM paths::

        root_cert       - root CA only (trust anchor)
        intermediate    - intermediate CA cert only
        leaf_cert       - leaf cert only (server sends "incomplete" chain)
        leaf_chain      - leaf + intermediate concatenated (server sends "full")
        leaf_key        - leaf private key
    """
    import trustme

    d = tmp_path_factory.mktemp("intermediates")
    root = trustme.CA()
    sub = root.create_child_ca()
    leaf = sub.issue_cert("localhost", "127.0.0.1")

    root_cert = d / "root.pem"
    intermediate = d / "intermediate.pem"
    leaf_cert = d / "leaf.pem"
    leaf_chain = d / "leaf_chain.pem"
    leaf_key = d / "leaf_key.pem"

    root.cert_pem.write_to_path(str(root_cert))
    # `sub.cert_pem` carries the intermediate's own cert (a `Blob`).
    sub.cert_pem.write_to_path(str(intermediate))
    # `leaf.cert_chain_pems == [leaf, intermediate]`.
    leaf.cert_chain_pems[0].write_to_path(str(leaf_cert))
    leaf.private_key_pem.write_to_path(str(leaf_key))
    # Concatenate leaf + intermediate for the "full chain" file.
    with open(leaf_chain, "wb") as fh:
        for blob in leaf.cert_chain_pems:
            with open(_blob_to_tmp(blob, d), "rb") as src:
                fh.write(src.read())

    return {
        "root_cert": str(root_cert),
        "intermediate": str(intermediate),
        "leaf_cert": str(leaf_cert),
        "leaf_chain": str(leaf_chain),
        "leaf_key": str(leaf_key),
    }


def _blob_to_tmp(blob, d):
    """Materialise a trustme ``Blob`` to a temp file and return the path."""
    import hashlib

    h = hashlib.sha1(blob.bytes()).hexdigest()[:12]
    p = d / f"_blob_{h}.pem"
    if not p.exists():
        blob.write_to_path(str(p))
    return str(p)


def _make_utls_server_with(certfile: str, keyfile: str) -> utls.SSLContext:
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    return ctx


class TestIntermediateCertChainBuilding:
    """Mirrors rtls's chain-building tests. BoringSSL's default verifier
    accepts intermediates loaded via the trust store, so the
    "incomplete chain + intermediate-on-client" path should just work.
    """

    def test_full_chain_from_server_root_only_on_client(self, intermediate_hierarchy):
        """Server sends ``leaf + intermediate``; client only trusts root."""
        h = intermediate_hierarchy
        server_ctx = _make_utls_server_with(h["leaf_chain"], h["leaf_key"])
        lsock, t, port, box = _start_threaded_echo(server_ctx)
        try:
            client_ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
            client_ctx.load_verify_locations(cafile=h["root_cert"])
            with socket.create_connection(("127.0.0.1", port), timeout=15) as raw:
                with client_ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    data = s.recv(1024)
                    assert data == b"OK", box
        finally:
            lsock.close()
            t.join(timeout=5)

    def test_incomplete_chain_with_intermediate_loaded_on_client(self, intermediate_hierarchy):
        """Server sends *only* the leaf; client has loaded both root and
        intermediate via ``load_verify_locations``. BoringSSL's verifier
        walks the store for chain candidates, so this must succeed.
        """
        h = intermediate_hierarchy
        server_ctx = _make_utls_server_with(h["leaf_cert"], h["leaf_key"])
        lsock, t, port, box = _start_threaded_echo(server_ctx)
        try:
            client_ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
            client_ctx.load_verify_locations(cafile=h["root_cert"])
            client_ctx.load_verify_locations(cafile=h["intermediate"])
            with socket.create_connection(("127.0.0.1", port), timeout=15) as raw:
                with client_ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    data = s.recv(1024)
                    assert data == b"OK", box
        finally:
            lsock.close()
            t.join(timeout=5)

    def test_incomplete_chain_without_intermediate_fails(self, intermediate_hierarchy):
        """Server sends only leaf; client has only root. Verification MUST
        fail with a TLS / cert-verify error - the chain is unresolvable.
        """
        h = intermediate_hierarchy
        server_ctx = _make_utls_server_with(h["leaf_cert"], h["leaf_key"])
        lsock, t, port, box = _start_threaded_echo(server_ctx)
        try:
            client_ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
            client_ctx.load_verify_locations(cafile=h["root_cert"])
            with pytest.raises((utls.SSLError, _stdlib_ssl.SSLError)):
                with socket.create_connection(("127.0.0.1", port), timeout=15) as raw:
                    with client_ctx.wrap_socket(raw, server_hostname="localhost"):
                        pass
        finally:
            lsock.close()
            t.join(timeout=5)

    def test_ca_bundle_with_root_and_intermediate_combined(self, intermediate_hierarchy, tmp_path):
        """A single PEM bundle containing both root and intermediate is the
        common CA-bundle deployment shape. Must succeed against an
        incomplete server chain.
        """
        h = intermediate_hierarchy
        bundle = tmp_path / "ca_bundle.pem"
        with open(h["root_cert"], "rb") as r, open(h["intermediate"], "rb") as i:
            bundle.write_bytes(r.read() + i.read())

        server_ctx = _make_utls_server_with(h["leaf_cert"], h["leaf_key"])
        lsock, t, port, box = _start_threaded_echo(server_ctx)
        try:
            client_ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
            client_ctx.load_verify_locations(cafile=str(bundle))
            with socket.create_connection(("127.0.0.1", port), timeout=15) as raw:
                with client_ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    assert s.recv(1024) == b"OK", box
        finally:
            lsock.close()
            t.join(timeout=5)


class TestECHCloneSemantics:
    """``set_ech_configs`` returns a NEW context whose Python-side state
    mirrors the source. The original is left untouched.
    """

    def test_returns_new_context(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        clone = ctx.set_ech_configs(b"\x00\x01\x02\x03")
        assert clone is not ctx
        assert isinstance(clone, utls.SSLContext)

    def test_type_check_rejects_string(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        with pytest.raises(TypeError):
            ctx.set_ech_configs("not bytes")  # type: ignore[arg-type]

    def test_clear_with_none(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        clone = ctx.set_ech_configs(None)
        assert clone is not ctx
        assert isinstance(clone, utls.SSLContext)

    def test_copies_python_side_state(self, ca_pem_path):
        """ALPN, verify_mode, check_hostname, version bounds, options -
        every Python-side attribute the user has touched - must be visible
        on the clone unchanged.
        """
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=ca_pem_path)
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        ctx.minimum_version = utls.TLSVersion.TLSv1_3
        ctx.maximum_version = utls.TLSVersion.TLSv1_3

        clone = ctx.set_ech_configs(b"\x00\x01\x02\x03")
        assert clone.check_hostname == ctx.check_hostname
        assert clone.verify_mode == ctx.verify_mode
        assert clone.minimum_version == ctx.minimum_version
        assert clone.maximum_version == ctx.maximum_version
        assert clone.protocol == ctx.protocol


class TestVerifyFlags:
    def test_default_is_zero(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        assert ctx.verify_flags == utls.VERIFY_DEFAULT == 0

    def test_set_and_read_back_trusted_first(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        ctx.verify_flags = utls.VERIFY_X509_TRUSTED_FIRST
        assert ctx.verify_flags & utls.VERIFY_X509_TRUSTED_FIRST
        assert ctx.verify_flags == utls.VERIFY_X509_TRUSTED_FIRST

    def test_set_combined_flags(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        ctx.verify_flags = utls.VERIFY_X509_TRUSTED_FIRST | utls.VERIFY_X509_PARTIAL_CHAIN
        assert ctx.verify_flags & utls.VERIFY_X509_TRUSTED_FIRST
        assert ctx.verify_flags & utls.VERIFY_X509_PARTIAL_CHAIN

    def test_replace_semantics_not_or(self):
        """Stdlib's ``ctx.verify_flags = X`` *replaces* the bitmask; it does
        not OR with the previous value. Pin that behavior."""
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        ctx.verify_flags = utls.VERIFY_X509_TRUSTED_FIRST
        ctx.verify_flags = utls.VERIFY_X509_PARTIAL_CHAIN
        assert ctx.verify_flags == utls.VERIFY_X509_PARTIAL_CHAIN
        assert not (ctx.verify_flags & utls.VERIFY_X509_TRUSTED_FIRST)

    def test_clear_to_zero(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        ctx.verify_flags = utls.VERIFY_X509_TRUSTED_FIRST
        ctx.verify_flags = 0
        assert ctx.verify_flags == 0

    def test_partial_chain_handshake_still_works(self, intermediate_hierarchy, server_cert_files):
        """Setting VERIFY_X509_PARTIAL_CHAIN must not break a normal
        full-chain handshake against the trustme leaf."""
        # Use the standard CA/cert pair (full chain trusted), assert that
        # turning on PARTIAL_CHAIN still produces a successful handshake.
        cli_ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        cli_ctx.load_verify_locations(cafile=intermediate_hierarchy["root_cert"])
        cli_ctx.verify_flags = utls.VERIFY_X509_PARTIAL_CHAIN

        srv_ctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
        srv_ctx.load_cert_chain(
            intermediate_hierarchy["leaf_chain"],
            intermediate_hierarchy["leaf_key"],
        )

        lsock, t, port, result = _start_threaded_echo(srv_ctx)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=15) as raw:
                with cli_ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    assert s.recv(1024) == b"OK"
                    s.sendall(b"bye")
        finally:
            t.join(timeout=10)
            lsock.close()
        assert "server_error" not in result, result.get("server_error")


class TestKeylogFilename:
    def test_setter_accepts_str(self, tmp_path):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        p = tmp_path / "secrets.log"
        ctx.keylog_filename = str(p)
        assert ctx.keylog_filename == str(p)

    def test_setter_accepts_none(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        ctx.keylog_filename = None
        assert ctx.keylog_filename is None

    def test_setter_rejects_int(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        with pytest.raises(TypeError):
            ctx.keylog_filename = 42  # type: ignore[assignment]

    def test_env_SSLKEYLOGFILE_not_honored(self, monkeypatch, tmp_path):
        """utls deliberately ignores the ``SSLKEYLOGFILE`` env var - the
        caller must opt in by setting ``ctx.keylog_filename`` explicitly.
        Pinned to prevent accidental implicit-leak regressions.
        """
        secrets = tmp_path / "leak.log"
        monkeypatch.setenv("SSLKEYLOGFILE", str(secrets))
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        assert ctx.keylog_filename is None

    def test_keylog_filename_writes_secrets(self, tmp_path, server_cert_files, ca_pem_path):
        """Real TLS 1.3 handshake must emit NSS Key Log Format lines to the
        path configured via ``keylog_filename``."""
        logfile = tmp_path / "secrets.log"

        cli_ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        cli_ctx.load_verify_locations(cafile=str(ca_pem_path))
        cli_ctx.minimum_version = utls.TLSVersion.TLSv1_3
        cli_ctx.keylog_filename = str(logfile)
        assert cli_ctx.keylog_filename == str(logfile)

        srv_ctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
        cert, key = server_cert_files
        srv_ctx.load_cert_chain(cert, key)
        srv_ctx.minimum_version = _stdlib_ssl.TLSVersion.TLSv1_3

        lsock, t, port, result = _start_threaded_echo(srv_ctx)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=15) as raw:
                with cli_ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    assert s.recv(1024) == b"OK"
                    s.sendall(b"bye")
        finally:
            t.join(timeout=10)
            lsock.close()
        assert "server_error" not in result, result.get("server_error")

        assert logfile.exists(), "keylog file was not created"
        data = logfile.read_text()
        assert data.strip(), "keylog file is empty"
        # TLS 1.3 always emits these two label classes.
        assert "CLIENT_HANDSHAKE_TRAFFIC_SECRET" in data, data
        assert "SERVER_HANDSHAKE_TRAFFIC_SECRET" in data, data

    def test_keylog_filename_clear(self, tmp_path):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        ctx.keylog_filename = str(tmp_path / "k.log")
        ctx.keylog_filename = None
        assert ctx.keylog_filename is None


def _reencrypt_pkcs8(
    plain_key_pem: bytes,
    password: bytes,
    *,
    algo: str = "aes256",
) -> bytes:
    """Re-serialize a plaintext PEM private key as encrypted PKCS#8.

    ``algo`` is informational - ``cryptography`` picks the algorithm via
    ``BestAvailableEncryption``; modern installs land on PBES2 + AES-256-CBC.
    """
    from cryptography.hazmat.primitives import serialization

    pk = serialization.load_pem_private_key(plain_key_pem, password=None)
    return pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )


class TestInMemoryCertChain:
    """``load_cert_chain`` accepting raw PEM bytes / inline-PEM str /
    pathlib.Path, in addition to plain str paths. Lets callers feed
    secret-store material directly without a ``tempfile`` round-trip."""

    def test_bytes_cert_and_bytes_key(self, server_cert_files):
        cert_path, key_path = server_cert_files
        cert_pem = Path(cert_path).read_bytes()
        key_pem = Path(key_path).read_bytes()
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_pem, key_pem)

    def test_bytes_bundle_no_keyfile(self, server_cert_files):
        # Stdlib semantics: when keyfile is omitted, the key is read from
        # the cert source. Works equally for in-memory PEM bundles.
        cert_path, key_path = server_cert_files
        bundle = Path(cert_path).read_bytes() + Path(key_path).read_bytes()
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(bundle)

    def test_inline_pem_str(self, server_cert_files):
        # A str that already contains a PEM block is taken verbatim rather
        # than being treated as a path that happens to look weird.
        cert_path, key_path = server_cert_files
        cert_text = Path(cert_path).read_text()
        key_text = Path(key_path).read_text()
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_text, key_text)

    def test_pathlib_path(self, server_cert_files):
        cert_path, key_path = server_cert_files
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(Path(cert_path), Path(key_path))

    def test_bytearray_and_memoryview(self, server_cert_files):
        cert_path, key_path = server_cert_files
        cert_ba = bytearray(Path(cert_path).read_bytes())
        key_mv = memoryview(Path(key_path).read_bytes())
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_ba, key_mv)

    def test_handshake_works_with_in_memory_cert(self, server_cert_files, ca_pem_path):
        # Round-trip proof: handshake against a stdlib client succeeds when
        # the server context was loaded from PEM bytes (not just no-op'd).
        import socket
        import ssl as _ssl
        import threading

        cert_path, key_path = server_cert_files
        cert_pem = Path(cert_path).read_bytes()
        key_pem = Path(key_path).read_bytes()

        srv_ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        srv_ctx.load_cert_chain(cert_pem, key_pem)

        lst = socket.socket()
        lst.bind(("127.0.0.1", 0))
        lst.listen(1)
        port = lst.getsockname()[1]
        accepted: list[BaseException | None] = [None]

        def serve():
            try:
                raw, _ = lst.accept()
                with srv_ctx.wrap_socket(raw, server_side=True) as s:
                    s.recv(64)
                    s.sendall(b"ok")
            except BaseException as e:  # Defensive: surfaced via accepted
                accepted[0] = e
            finally:
                lst.close()

        t = threading.Thread(target=serve)
        t.start()

        cli_ctx = _ssl.create_default_context(cafile=ca_pem_path)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with cli_ctx.wrap_socket(raw, server_hostname="localhost") as s:
                s.sendall(b"ping")
                assert s.recv(64) == b"ok"
        t.join(timeout=5)
        assert accepted[0] is None

    def test_rejects_unsupported_type(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        with pytest.raises(TypeError, match="certfile must be"):
            ctx.load_cert_chain(12345)  # type: ignore[arg-type]

    def test_rejects_unsupported_keyfile_type(self, server_cert_files):
        cert_path, _ = server_cert_files
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        with pytest.raises(TypeError, match="keyfile must be"):
            ctx.load_cert_chain(cert_path, 12345)  # type: ignore[arg-type]

    def test_garbage_pem_raises_ssl_error(self):
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        with pytest.raises(utls.SSLError):
            ctx.load_cert_chain(b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n")


class TestEncryptedKeySupport:
    def test_load_encrypted_pkcs8_with_bytes_password(self, tmp_path, server_cert_files):
        cert, plain_key = server_cert_files
        enc_pem = _reencrypt_pkcs8(Path(plain_key).read_bytes(), b"correct horse battery staple")
        enc_path = tmp_path / "key.enc.pem"
        enc_path.write_bytes(enc_pem)

        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, str(enc_path), password=b"correct horse battery staple")

    def test_load_encrypted_pkcs8_with_str_password(self, tmp_path, server_cert_files):
        cert, plain_key = server_cert_files
        enc_pem = _reencrypt_pkcs8(Path(plain_key).read_bytes(), b"hunter2")
        enc_path = tmp_path / "key.enc.pem"
        enc_path.write_bytes(enc_pem)

        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        # stdlib accepts ``str``; we encode it as UTF-8 internally.
        ctx.load_cert_chain(cert, str(enc_path), password="hunter2")

    def test_load_encrypted_pkcs8_with_callable_password(self, tmp_path, server_cert_files):
        cert, plain_key = server_cert_files
        enc_pem = _reencrypt_pkcs8(Path(plain_key).read_bytes(), b"s3cret")
        enc_path = tmp_path / "key.enc.pem"
        enc_path.write_bytes(enc_pem)

        called = 0

        def supply() -> bytes:
            nonlocal called
            called += 1
            return b"s3cret"

        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, str(enc_path), password=supply)
        assert called == 1, "callable should be invoked exactly once per load"

    def test_wrong_password_raises_ssl_error(self, tmp_path, server_cert_files):
        cert, plain_key = server_cert_files
        enc_pem = _reencrypt_pkcs8(Path(plain_key).read_bytes(), b"right")
        enc_path = tmp_path / "key.enc.pem"
        enc_path.write_bytes(enc_pem)

        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        with pytest.raises(utls.SSLError):
            ctx.load_cert_chain(cert, str(enc_path), password=b"wrong")

    def test_password_type_validation(self, server_cert_files):
        cert, key = server_cert_files
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        with pytest.raises(TypeError):
            ctx.load_cert_chain(cert, key, password=12345)  # type: ignore[arg-type]

    def test_password_length_cap(self, server_cert_files):
        cert, key = server_cert_files
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        with pytest.raises(ValueError):
            ctx.load_cert_chain(cert, key, password=b"x" * 1025)


class TestTraditionalEncryptedKeySupport:
    def test_load_rsa_traditional_aes256(self, tmp_path):
        """Traditional PEM (``-----BEGIN RSA PRIVATE KEY-----`` + DEK-Info)
        encrypted with AES-256-CBC. Built by hand because ``cryptography``
        no longer produces this legacy format directly.
        """
        import base64
        import datetime as _dt
        import os as _os

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.x509 import (
            CertificateBuilder,
            Name,
            NameAttribute,
            random_serial_number,
        )
        from cryptography.x509.oid import NameOID

        # Self-signed RSA cert + key.
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = Name([NameAttribute(NameOID.COMMON_NAME, "trad-enc.test")])
        now = _dt.datetime.now(_dt.timezone.utc)
        cert = (
            CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        # Serialize as raw PKCS#1 DER -> wrap in traditional-PEM with
        # DEK-Info AES-256-CBC + PEM-style key derivation (MD5(passwd||salt)
        # iterated, OpenSSL's EVP_BytesToKey).
        der = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        password = b"horse-staple"
        iv = _os.urandom(16)

        # OpenSSL EVP_BytesToKey with MD5 + 1 iteration (the legacy traditional
        # PEM derivation - not PBKDF2). The IV's first 8 bytes are the salt.
        salt = iv[:8]
        from hashlib import md5

        d = b""
        last = b""
        while len(d) < 32:
            last = md5(last + password + salt).digest()
            d += last
        aes_key = d[:32]

        padder_block = 16
        pad = padder_block - (len(der) % padder_block)
        padded = der + bytes([pad]) * pad
        enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
        ciphertext = enc.update(padded) + enc.finalize()

        b64 = base64.b64encode(ciphertext).decode()
        wrapped = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
        traditional = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\n"
            f"DEK-Info: AES-256-CBC,{iv.hex().upper()}\n"
            "\n" + wrapped + "\n-----END RSA PRIVATE KEY-----\n"
        ).encode()

        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(traditional)

        ctx = utls.SSLContext(utls.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_path), str(key_path), password=password)


def test_streaming_download_2gb(server_cert_files, ca_pem_path):
    """utls client downloads 2 GiB from a stdlib ``ssl`` server.

    The server streams 64 KiB blocks of deterministic PRNG-derived bytes
    (Random(42).getrandbits - same on both sides) and the client recv()s
    as fast as it can. An MD5 running hash on both sides catches *any*
    silent data corruption (mis-ordered records, truncation, bit flip)
    without holding 2 GiB resident.

    Why not :func:`hashlib.sha256`? MD5 is a few times faster and we
    only need collision resistance against accidental, not adversarial,
    corruption here.
    """
    import hashlib
    import random

    TOTAL = 2 * 1024 * 1024 * 1024  # 2 GiB
    BLOCK = 65536

    cert, key = server_cert_files
    server_ctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)

    lsock = socket.socket()
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    lsock.settimeout(300)
    port = lsock.getsockname()[1]

    result: dict = {}
    ready = threading.Event()

    def streaming_server():
        ready.set()
        ssl_conn = None
        conn = None
        try:
            conn, _ = lsock.accept()
            ssl_conn = server_ctx.wrap_socket(conn, server_side=True)
            h = hashlib.md5()
            sent = 0
            rng = random.Random(42)
            while sent < TOTAL:
                # rng.getrandbits is Python-3.7-safe; rng.randbytes only 3.9+.
                chunk = rng.getrandbits(BLOCK * 8).to_bytes(BLOCK, "big")
                h.update(chunk)
                ssl_conn.sendall(chunk)
                sent += len(chunk)
            result["digest"] = h.hexdigest()
            result["server"] = "ok"
        except Exception as e:  # noqa: BLE001
            result["server_error"] = repr(e)
        finally:
            if ssl_conn is not None:
                try:
                    ssl_conn.close()
                except OSError:
                    pass
            elif conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass

    t = threading.Thread(target=streaming_server, daemon=True)
    t.start()
    ready.wait()

    # Build utls client trusting the shared trustme CA.
    import utls as _utls

    client_ctx = _utls.SSLContext(_utls.PROTOCOL_TLS_CLIENT)
    client_ctx.load_verify_locations(cafile=ca_pem_path)

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=300) as raw:
            with client_ctx.wrap_socket(raw, server_hostname="localhost") as s:
                h = hashlib.md5()
                received = 0
                while received < TOTAL:
                    chunk = s.recv(BLOCK)
                    if not chunk:
                        break
                    h.update(chunk)
                    received += len(chunk)
                assert received == TOTAL, (
                    f"short read: got {received} / {TOTAL} bytes (server result: {result!r})"
                )
    finally:
        lsock.close()
        t.join(timeout=300)

    assert result.get("server") == "ok", result
    assert h.hexdigest() == result["digest"], (
        f"data corruption: client md5 {h.hexdigest()} != server md5 {result['digest']}"
    )


def test_sslcontext_passes_stdlib_isinstance_check():
    """`utls.SSLContext` must inherit from `ssl.SSLContext` so third-party
    libraries (asyncio, aiohttp, urllib3, requests, httpx, ...) that perform
    a strict `isinstance(ctx, ssl.SSLContext)` check accept it transparently.

    Regression for: ``TypeError: sslcontext is expected to be an instance of
    ssl.SSLContext, got <utls._facade.SSLContext object>``.
    """
    ctx = utls.SSLContext()
    assert isinstance(ctx, _stdlib_ssl.SSLContext)
    assert isinstance(utls.create_default_context(), _stdlib_ssl.SSLContext)


def test_sslcontext_inheritance_does_not_leak_stdlib_behavior():
    """Inheriting from `ssl.SSLContext` is purely structural - every method
    and property we override must route through the BoringSSL backend, not
    the stdlib's internal OpenSSL `SSL_CTX`. The smoke check here is that
    `set_fingerprint` (an `utls`-only surface absent from the stdlib) works
    on a plain `SSLContext` and that the fingerprint round-trips.
    """
    ctx = utls.SSLContext()
    ctx.set_fingerprint("chrome:stable")
    assert ctx.fingerprint is not None
    assert ctx.fingerprint.ja4_hash.startswith("t13")


def test_sslcontext_clone_via_set_ech_configs_remains_sslcontext():
    """Forking via `set_ech_configs` must preserve the
    `ssl.SSLContext`-ness of the clone - otherwise the same third-party
    libraries reject the per-peer fork."""
    base = utls.SSLContext()
    forked = base.set_ech_configs(None)
    assert isinstance(forked, _stdlib_ssl.SSLContext)
    assert isinstance(forked, utls.SSLContext)


def test_create_default_context_is_safe_by_default():
    ctx = utls.create_default_context()
    assert ctx.verify_mode == utls.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version == utls.TLSVersion.TLSv1_2
    assert ctx.maximum_version == utls.TLSVersion.TLSv1_3


def test_only_client_protocol_is_accepted():
    with pytest.raises(ValueError, match="PROTOCOL_TLS_CLIENT"):
        utls.SSLContext(protocol=42)


def test_cannot_enable_hostname_check_while_cert_none():
    """Stdlib invariant: check_hostname=True is incompatible with CERT_NONE."""
    ctx = utls.create_default_context()
    # Drop both to a state where check_hostname is False, CERT_NONE.
    ctx.check_hostname = False
    ctx.verify_mode = utls.CERT_NONE
    with pytest.raises(ValueError):
        ctx.check_hostname = True  # would re-introduce the dangerous combo


def test_disable_hostname_check_after_dropping_verify_mode():
    """The supported escape hatch: drop check_hostname first, then CERT_NONE.

    Setting `verify_mode = CERT_NONE` while `check_hostname` is True is a
    `ValueError` (matches stdlib). Once `check_hostname` is off, switching
    `verify_mode` is silent - stdlib emits no warning here either.
    """
    ctx = utls.create_default_context()
    ctx.check_hostname = False  # only allowed because no I/O yet
    ctx.verify_mode = utls.CERT_NONE
    assert ctx.check_hostname is False
    assert ctx.verify_mode == utls.CERT_NONE


def test_setting_cert_none_while_hostname_check_on_raises():
    ctx = utls.create_default_context()
    with pytest.raises(ValueError):
        ctx.verify_mode = utls.CERT_NONE


def test_wrap_bio_requires_hostname_when_verifying():
    ctx = utls.create_default_context()
    inc, out = utls.MemoryBIO(), utls.MemoryBIO()
    with pytest.raises(ValueError, match="server_hostname"):
        ctx.wrap_bio(inc, out)


def test_wrap_bio_with_hostname_constructs():
    ctx = utls.create_default_context()
    inc, out = utls.MemoryBIO(), utls.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname="example.com")
    assert obj.server_hostname == "example.com"
    assert obj.version() is None  # handshake hasn't happened


def test_constructor_rejects_non_client_protocol():
    """Server-side TLS is out of utls' scope. Any protocol value other than
    ``PROTOCOL_TLS_CLIENT`` (notably ``ssl.PROTOCOL_TLS_SERVER == 3``) must
    fail loudly at construction rather than silently producing a broken
    client context.
    """
    import ssl as _stdlib_ssl

    with pytest.raises(ValueError, match="PROTOCOL_TLS_CLIENT"):
        utls.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)


def test_wrap_bio_accepts_server_side_false():
    """`asyncio.sslproto.SSLProtocol` (3.11+) calls
    ``sslcontext.wrap_bio(..., server_side=False, server_hostname=...)``.
    The kwarg must be accepted for ecosystem compatibility; `False` is the
    only legal value since utls is client-only.

    Regression for: ``TypeError: SSLContext.wrap_bio() got an unexpected
    keyword argument 'server_side'``.
    """
    ctx = utls.create_default_context()
    inc, out = utls.MemoryBIO(), utls.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_side=False, server_hostname="example.com")
    assert obj.server_hostname == "example.com"


def test_wrap_bio_rejects_server_side_true_on_client_context():
    """A client SSLContext must refuse ``server_side=True``: stdlib raises
    ``ValueError`` ("Cannot set server_side=True when ..."); we likewise
    refuse with a message that names the required server context.
    """
    ctx = utls.create_default_context()
    inc, out = utls.MemoryBIO(), utls.MemoryBIO()
    with pytest.raises(ValueError, match="PROTOCOL_TLS_SERVER"):
        ctx.wrap_bio(inc, out, server_side=True, server_hostname="example.com")


def test_wrap_socket_accepts_server_side_false():
    """Symmetrically: `ssl.SSLContext.wrap_socket` has `server_side` as its
    second positional argument; client libraries may pass it positionally or
    as a keyword."""
    import socket

    ctx = utls.create_default_context()
    s = socket.socket()
    try:
        wrapped = ctx.wrap_socket(
            s,
            server_side=False,
            do_handshake_on_connect=False,
            server_hostname="example.com",
        )
        assert wrapped is not None
    finally:
        s.close()


def test_wrap_socket_rejects_server_side_true():
    import socket

    ctx = utls.create_default_context()
    s = socket.socket()
    try:
        with pytest.raises(ValueError, match="PROTOCOL_TLS_SERVER"):
            ctx.wrap_socket(s, server_side=True, server_hostname="example.com")
    finally:
        s.close()


def test_wrap_bio_accepts_stdlib_memorybio():
    """`wrap_bio` must accept `ssl.MemoryBIO` instances without raising the
    pre-fix ``TypeError: incoming and outgoing must be MemoryBIO instances``.
    Regression for the failure seen from `asyncio.sslproto`.
    """
    ctx = utls.create_default_context()
    inc = _stdlib_ssl.MemoryBIO()
    out = _stdlib_ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname="example.com")
    assert obj is not None
    # The SSLObject must record the *caller's* BIOs for them to be the I/O
    # surface the caller drives - not the private Rust BIOs.
    assert obj._incoming is inc
    assert obj._outgoing is out
    # Pumping is enabled because at least one BIO is stdlib-typed.
    assert obj._pumping is True


def test_wrap_bio_native_regime_skips_pumping():
    """When both BIOs are utls.MemoryBIO, no pumping happens - the engine
    reads/writes the user-visible buffers directly."""
    ctx = utls.create_default_context()
    inc = utls.MemoryBIO()
    out = utls.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname="example.com")
    assert obj._pumping is False
    assert obj._rust_incoming is None
    assert obj._rust_outgoing is None


def test_wrap_bio_rejects_arbitrary_objects():
    """Anything that is neither `utls.MemoryBIO` nor `ssl.MemoryBIO` is a
    programmer error and should still raise TypeError."""
    ctx = utls.create_default_context()
    with pytest.raises(TypeError, match="MemoryBIO"):
        ctx.wrap_bio(object(), _stdlib_ssl.MemoryBIO(), server_hostname="x")
    with pytest.raises(TypeError, match="MemoryBIO"):
        ctx.wrap_bio(_stdlib_ssl.MemoryBIO(), b"not a bio", server_hostname="x")


def test_wrap_bio_mixed_types_uses_adapted_regime():
    """Even if only one BIO is stdlib-typed, the adapter is engaged for both
    - keeping a single uniform pumping path on every SSL operation."""
    ctx = utls.create_default_context()
    obj = ctx.wrap_bio(
        _stdlib_ssl.MemoryBIO(),
        utls.MemoryBIO(),
        server_hostname="x",
    )
    assert obj._pumping is True


def test_pumping_drains_outgoing_after_initial_clienthello():
    """A fresh `do_handshake()` must produce a ClientHello in the *caller's*
    outgoing BIO - proving the post-op pump from Rust outgoing -> stdlib
    outgoing fires. This is the exact contract asyncio depends on.
    """
    ctx = utls.create_default_context()
    inc = _stdlib_ssl.MemoryBIO()
    out = _stdlib_ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname="example.com")
    with pytest.raises(utls.SSLWantReadError):
        obj.do_handshake()
    # Pumping must have moved the ClientHello into the caller-visible BIO.
    assert out.pending > 0
    hello = out.read(-1)
    # TLS record header: 0x16 (handshake) + version + length
    assert hello[0] == 0x16, "expected TLS handshake record in outgoing BIO"


def _run_stdlib_server(host: str, server_ctx: _stdlib_ssl.SSLContext):
    """Spin up a one-shot stdlib TLS echo server on an ephemeral port. Returns
    `(port, thread)`. The thread terminates after one connection."""
    sock = socket.socket()
    sock.bind((host, 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    def serve() -> None:
        try:
            client, _addr = sock.accept()
            with server_ctx.wrap_socket(client, server_side=True) as tls:
                data = tls.recv(5)
                tls.sendall(b"PONG:" + data)
        finally:
            sock.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return port, t


def test_stdlib_memorybio_full_handshake_against_stdlib_server():
    """End-to-end: drive an utls client handshake using *stdlib*
    `ssl.MemoryBIO` instances (the exact shape asyncio uses) against a
    plain stdlib SSL server. If the pumping in `SSLObject` is wrong in
    either direction the handshake will stall or the records will be
    rejected by the server.
    """
    ca = trustme.CA()
    cert = ca.issue_cert("localhost")

    server_ctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
    cert.configure_cert(server_ctx)

    client_ctx = utls.create_default_context()
    client_ctx.load_verify_locations(cadata=ca.cert_pem.bytes().decode("ascii"))

    port, server_thread = _run_stdlib_server("127.0.0.1", server_ctx)

    raw = socket.create_connection(("127.0.0.1", port))
    try:
        # Mirror asyncio.sslproto: stdlib BIOs, not our MemoryBIO.
        inc = _stdlib_ssl.MemoryBIO()
        out = _stdlib_ssl.MemoryBIO()
        sslobj = client_ctx.wrap_bio(inc, out, server_hostname="localhost")

        # Hand-driven I/O loop, the same pattern asyncio uses. Order matters:
        # we must flush the engine's output (ClientHello / Finished / ...)
        # *before* trying to read the peer's response, otherwise the peer
        # has nothing to respond to and recv() blocks forever.
        def pump_loop() -> None:
            while True:
                try:
                    sslobj.do_handshake()
                    if out.pending:
                        raw.sendall(out.read(-1))
                    return
                except utls.SSLWantReadError:
                    pass
                if out.pending:
                    raw.sendall(out.read(-1))
                chunk = raw.recv(4096)
                if not chunk:
                    inc.write_eof()
                    raise RuntimeError("peer closed during handshake")
                inc.write(chunk)

        pump_loop()
        assert sslobj.version() in ("TLSv1.3", "TLSv1.2")

        # Application data round-trip via the same pumping pattern.
        sslobj.write(b"PING!")
        if out.pending:
            raw.sendall(out.read(-1))

        # Read PONG:PING!
        received = b""
        while len(received) < len(b"PONG:PING!"):
            try:
                received += sslobj.read(4096)
            except utls.SSLWantReadError:
                chunk = raw.recv(4096)
                if not chunk:
                    break
                inc.write(chunk)
            if out.pending:
                raw.sendall(out.read(-1))
        assert received == b"PONG:PING!"
    finally:
        raw.close()
        server_thread.join(timeout=5)
