from __future__ import annotations

import socket
import ssl as _stdlib_ssl
import threading

import pytest
import trustme

import utls



def test_sslsocket_exposes_socket_type_family_proto():
    """`SSLSocket.type` must match the wrapped socket's type, same for family
    and proto. urllib3 asserts this on every reused connection."""
    ctx = utls.create_default_context()
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ssock = ctx.wrap_socket(raw, do_handshake_on_connect=False,
                                server_hostname="example.com")
        assert ssock.type == socket.SOCK_STREAM
        assert ssock.family == socket.AF_INET
        assert ssock.proto == raw.proto
    finally:
        raw.close()



def _serve_once(server_ctx: _stdlib_ssl.SSLContext) -> tuple[int, threading.Thread]:
    """Spin up a one-shot stdlib SSL echo server on an ephemeral port."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    def serve() -> None:
        try:
            client, _ = sock.accept()
            try:
                with server_ctx.wrap_socket(client, server_side=True) as tls:
                    try:
                        tls.recv(1)
                    except (OSError, _stdlib_ssl.SSLError):
                        pass
            except (OSError, _stdlib_ssl.SSLError):
                pass
        finally:
            sock.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return port, t


def _connect_and_handshake(port: int, client_ctx: utls.SSLContext, hostname: str):
    raw = socket.create_connection(("127.0.0.1", port))
    ssock = client_ctx.wrap_socket(raw, server_hostname=hostname)
    return ssock


@pytest.fixture
def real_handshake():
    """Yield an `(SSLSocket, server_thread)` pair with a completed handshake
    against an in-process stdlib server using a trustme-issued cert with
    multiple SAN entries."""
    ca = trustme.CA()
    cert = ca.issue_cert("localhost", "alt.localhost")

    server_ctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
    cert.configure_cert(server_ctx)

    client_ctx = utls.create_default_context()
    client_ctx.load_verify_locations(cadata=ca.cert_pem.bytes().decode())

    port, t = _serve_once(server_ctx)
    ssock = _connect_and_handshake(port, client_ctx, "localhost")
    try:
        yield ssock, t
    finally:
        try:
            ssock.send(b"x")
        except Exception:
            pass
        try:
            ssock.close()
        except Exception:
            pass
        t.join(timeout=5)


def test_getpeercert_binary_form_returns_der_leaf(real_handshake):
    ssock, _ = real_handshake
    der = ssock.getpeercert(binary_form=True)
    assert isinstance(der, bytes)
    # DER sequences begin with 0x30 (SEQUENCE).
    assert der[0] == 0x30
    # Sanity-check by re-parsing through stdlib's PEM/DER helper.
    pem = _stdlib_ssl.DER_cert_to_PEM_cert(der)
    assert "BEGIN CERTIFICATE" in pem


def test_getpeercert_dict_has_stdlib_shape(real_handshake):
    """The dict must contain the keys ecosystem code reads. We compare key
    presence and types against the stdlib contract documented in
    `ssl.SSLSocket.getpeercert`."""
    ssock, _ = real_handshake
    info = ssock.getpeercert()
    assert isinstance(info, dict)
    # Required fields.
    for key in ("subject", "issuer", "version", "serialNumber",
                "notBefore", "notAfter", "subjectAltName"):
        assert key in info, f"missing key: {key}"
    # Versions in the wild are 1, 2, or 3 - 1-indexed per stdlib.
    assert info["version"] in (1, 2, 3)
    # Serial is uppercase hex.
    assert info["serialNumber"]
    assert info["serialNumber"] == info["serialNumber"].upper()
    assert all(c in "0123456789ABCDEF" for c in info["serialNumber"])
    # Dates use ASN1_TIME_print format ending in "GMT".
    assert info["notBefore"].endswith(" GMT")
    assert info["notAfter"].endswith(" GMT")


def test_getpeercert_subject_alt_name_shape(real_handshake):
    """SAN must be a tuple of (kind, value) pairs with stdlib labels.
    The trustme cert above has DNS SANs for both names."""
    ssock, _ = real_handshake
    info = ssock.getpeercert()
    san = info["subjectAltName"]
    assert isinstance(san, tuple)
    assert len(san) >= 2
    # Each entry is a 2-tuple of strings.
    for entry in san:
        assert isinstance(entry, tuple) and len(entry) == 2
        kind, value = entry
        assert isinstance(kind, str) and isinstance(value, str)
    # The two DNS names should appear.
    dns_values = {v for k, v in san if k == "DNS"}
    assert "localhost" in dns_values
    assert "alt.localhost" in dns_values


def test_getpeercert_subject_and_issuer_are_rdn_tuples(real_handshake):
    """subject/issuer are tuple-of-RDNs-of-(attr, value) - the shape
    ssl.match_hostname (deprecated) and urllib3 walk through."""
    ssock, _ = real_handshake
    info = ssock.getpeercert()
    for field in ("subject", "issuer"):
        rdns = info[field]
        assert isinstance(rdns, tuple), f"{field} not a tuple"
        for rdn in rdns:
            assert isinstance(rdn, tuple)
            for pair in rdn:
                assert isinstance(pair, tuple) and len(pair) == 2
                attr, value = pair
                assert isinstance(attr, str)
                assert isinstance(value, str)
                # We must surface the long/short OBJ name, not the raw OID,
                # whenever BoringSSL knows the OID. trustme certs only use
                # well-known attrs (CN, O, OU at most), so no dotted forms.
                assert not attr.startswith("0.") and not attr.startswith("1.") \
                    and not attr.startswith("2."), (
                        f"attr {attr!r} came through as numeric OID - "
                        "OBJ_obj2txt(buf, len, obj, 0) should have resolved it"
                    )


def test_getpeercert_san_value_with_colons_not_truncated():
    """A SAN value with embedded colons (IPv6, URI) must not be truncated by
    naive single-split parsing of `GENERAL_NAME_print` output. Regression for
    the split-on-':'-once-only contract.
    """
    ca = trustme.CA()
    # trustme accepts IPv6 strings - uses GEN_IPADD which prints as
    # "IP Address:::1" (kind = "IP Address", value = "::1").
    cert = ca.issue_cert("::1")

    server_ctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
    cert.configure_cert(server_ctx)
    client_ctx = utls.create_default_context()
    client_ctx.load_verify_locations(cadata=ca.cert_pem.bytes().decode())

    port, t = _serve_once(server_ctx)
    raw = socket.create_connection(("127.0.0.1", port))
    try:
        # IP-SAN routing: server_hostname="::1" must match the iPAddress SAN.
        ssock = client_ctx.wrap_socket(raw, server_hostname="::1")
        info = ssock.getpeercert()
        san = info["subjectAltName"]
        ip_entries = [v for k, v in san if k == "IP Address"]
        assert ip_entries, f"no IP Address SAN: {san!r}"
        # `GENERAL_NAME_print` emits the uncompressed IPv6 form. The point of
        # this test is that the multi-colon *value* survived `splitn(2, ':')`
        # in `walk_san`; a naive `split(':')` would have produced kind="IP"
        # and dropped the rest. We assert exactly that contract.
        assert any(":" in v for v in ip_entries), (
            f"IPv6 value lost its colons during parsing: {san!r}"
        )
        # And the value should be the full address, not a truncated prefix.
        assert ip_entries[0] == "0:0:0:0:0:0:0:1"
        ssock.close()
    finally:
        t.join(timeout=5)
