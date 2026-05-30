from __future__ import annotations

import socket
import ssl as _stdlib_ssl
import threading

import pytest
import trustme

import utls


@pytest.mark.parametrize("host,port", [
    ("www.google.com", 443),
    ("cloudflare.com", 443),
])
def test_default_context_handshake(host: str, port: int, requires_network):
    ctx = utls.create_default_context()
    with socket.create_connection((host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            assert s.version() in {"TLSv1.3", "TLSv1.2"}
            s.sendall(
                f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
            )
            chunk = s.recv(4096)
            assert chunk.startswith(b"HTTP/"), chunk[:40]


def test_chrome_preset_handshake_against_google(requires_network):
    ctx = utls.create_default_context()
    ctx.set_fingerprint("chrome:131")
    host = "www.google.com"
    with socket.create_connection((host, 443), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            assert s.selected_alpn_protocol() in {"h2", "http/1.1"}


def test_verification_rejects_bad_cn():
    """Connecting with ``server_hostname`` that doesn't match any SAN on the
    presented cert must produce ``SSLCertVerificationError``.

    Done locally with ``trustme`` rather than against badssl.com because
    third-party endpoints are flaky on GitHub's Windows runners (RST mid-
    handshake, opaque ``TimeoutError``) for reasons unrelated to what this
    test asserts. The verification property under test - "leaf cert SANs
    don't include the requested hostname so the handshake fails locally" -
    is independent of any real-world infrastructure.
    """
    ca = trustme.CA()
    # Cert vouches only for "right.example.com"; client will ask for
    # "wrong.example.com", which must be rejected by hostname verification.
    server_cert = ca.issue_cert("right.example.com")
    server_ctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_ctx)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _run():
        # Server-side: accept, attempt handshake, swallow whatever fallout
        # the client-side rejection causes (RST / SSLError / EOF).
        try:
            client, _ = srv.accept()
            try:
                tls = server_ctx.wrap_socket(client, server_side=True)
                try:
                    tls.recv(64)
                except (_stdlib_ssl.SSLError, ConnectionError, OSError):
                    pass
                finally:
                    try:
                        tls.close()
                    except OSError:
                        pass
            except (_stdlib_ssl.SSLError, ConnectionError, OSError):
                try:
                    client.close()
                except OSError:
                    pass
        finally:
            srv.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    client_ctx = utls.create_default_context()
    client_ctx.load_verify_locations(cadata=ca.cert_pem.bytes().decode("ascii"))

    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        with pytest.raises(utls.SSLCertVerificationError):
            client_ctx.wrap_socket(raw, server_hostname="wrong.example.com")
    finally:
        try:
            raw.close()
        except OSError:
            pass
        t.join(timeout=5)


@pytest.mark.parametrize("host", ["www.cloudflare.com", "blog.cloudflare.com"])
def test_chrome_fingerprint_handshakes_through_brotli_cert_compression(host, requires_network):
    ctx = utls.SSLContext()
    ctx.set_fingerprint("chrome:stable")
    ctx.load_default_certs()
    with socket.create_connection((host, 443), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            assert s.version() in {"TLSv1.3", "TLSv1.2"}
            # ALPN must still negotiate normally, cert compression must
            # not break later handshake steps.
            assert s.selected_alpn_protocol() in {"h2", "http/1.1"}


def test_set_alpn_protocols_after_set_fingerprint_overrides_fingerprint_alpn(requires_network):
    host = "www.cloudflare.com"
    ctx = utls.SSLContext()
    ctx.set_fingerprint("chrome:stable")
    ctx.set_alpn_protocols(["http/1.1"])
    ctx.load_default_certs()
    with socket.create_connection((host, 443), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            assert s.selected_alpn_protocol() == "http/1.1", (
                f"expected http/1.1, server negotiated "
                f"{s.selected_alpn_protocol()!r} (fingerprint ALPN leaked)"
            )
