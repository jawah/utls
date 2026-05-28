from __future__ import annotations

import http.server
import socket
import ssl as _stdlib_ssl
import threading
from typing import Iterator

import pytest

import utls

urllib3 = pytest.importorskip("urllib3")


class _EchoHandler(http.server.BaseHTTPRequestHandler):
    """Tiny GET/POST echo. Body returned verbatim with a Content-Length so
    urllib3-future's hface backend doesn't need chunked decoding."""

    def do_GET(self) -> None:  # noqa: N802
        body = b"hello-get:" + self.path.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object, **kwargs: object) -> None:  # noqa: D401
        # Silence the default stderr access log; tests run hot.
        return


@pytest.fixture
def local_https(server_cert_files, ca_pem_path) -> Iterator[tuple[str, int, str]]:
    """Start a stdlib HTTPS server on a random localhost port.

    Yields ``(host, port, ca_pem_path)``. ALPN is pinned to ``http/1.1``
    because urllib3-future will gladly try HTTP/2 over hface otherwise,
    and BaseHTTPServer doesn't speak frames.
    """
    cert, key = server_cert_files
    server_ctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)
    server_ctx.set_alpn_protocols(["http/1.1"])

    httpd = http.server.HTTPServer(("127.0.0.1", 0), _EchoHandler)
    httpd.socket = server_ctx.wrap_socket(httpd.socket, server_side=True)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield "localhost", port, ca_pem_path
    finally:
        httpd.shutdown()
        httpd.server_close()
        t.join(timeout=5)


def _make_client_ctx(ca_pem_path: str) -> utls.SSLContext:
    """Build an utls client context that trusts the test CA and speaks
    HTTP/1.1 over ALPN."""
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=ca_pem_path)
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx



class TestPreFlightProbes:
    """Compat surfaces that urllib3-future touches *before* the handshake;
    cheap unit tests so a future regression surfaces here instead of
    deep inside a connection-pool stack trace."""

    def test_options_supports_membership_in(self):
        """``urllib3.util.ssl_.is_capable_for_quic`` uses
        ``ssl.OP_NO_TLSv1_3 in ctx.options`` - that's a flag-enum
        membership test, not an integer ``__contains__``."""
        ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
        # Default options does not contain OP_NO_TLSv1_3.
        assert _stdlib_ssl.OP_NO_TLSv1_3 not in ctx.options
        ctx.options |= utls.OP_NO_TLSv1_3
        assert _stdlib_ssl.OP_NO_TLSv1_3 in ctx.options

    def test_sslsocket_exposes_getsockopt(self, local_https):
        """urllib3-future calls ``sock.getsockopt(SOL_SOCKET, SO_KEEPALIVE)``
        on the wrapped TLS socket inside ``enable_keepalive``."""
        host, port, ca = local_https
        cli_ctx = _make_client_ctx(ca)
        with socket.create_connection((host, port), timeout=5) as raw:
            with cli_ctx.wrap_socket(raw, server_hostname=host) as s:
                # Just exercising the codepath - value isn't asserted because
                # the kernel default depends on the platform.
                _ = s.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE)
                # Round-trip a set as well.
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                # macOS returns the raw flag bit (e.g. 8 for SO_KEEPALIVE),
                # Linux/Windows return a normalised 0/1. Both are "truthy
                # means enabled" - that's all urllib3-future cares about.
                assert s.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) != 0


class TestEndToEnd:
    """Full request lifecycle through urllib3-future's HTTPSConnectionPool."""

    def test_get(self, local_https):
        host, port, ca = local_https
        pool = urllib3.HTTPSConnectionPool(
            host,
            port=port,
            ssl_context=_make_client_ctx(ca),
            timeout=10,
            retries=False,
        )
        r = pool.request("GET", "/probe")
        assert r.status == 200
        assert r.data == b"hello-get:/probe"

    def test_post_body_roundtrip(self, local_https):
        host, port, ca = local_https
        pool = urllib3.HTTPSConnectionPool(
            host,
            port=port,
            ssl_context=_make_client_ctx(ca),
            timeout=10,
            retries=False,
        )
        body = b"x" * 4096
        r = pool.request("POST", "/echo", body=body)
        assert r.status == 200
        assert r.data == body

    def test_poolmanager(self, local_https):
        host, port, ca = local_https
        pm = urllib3.PoolManager(ssl_context=_make_client_ctx(ca))
        r = pm.request("GET", f"https://{host}:{port}/p", retries=False, timeout=10)
        assert r.status == 200
        assert r.data == b"hello-get:/p"

    def test_keepalive_two_requests_same_pool(self, local_https):
        """urllib3-future reuses a single connection across requests when
        the response carries ``Content-Length``. Verifies our SSLSocket
        survives a second send/recv round-trip."""
        host, port, ca = local_https
        pool = urllib3.HTTPSConnectionPool(
            host,
            port=port,
            ssl_context=_make_client_ctx(ca),
            timeout=10,
            retries=False,
        )
        r1 = pool.request("GET", "/one")
        r2 = pool.request("GET", "/two")
        assert (r1.status, r2.status) == (200, 200)
        assert r1.data == b"hello-get:/one"
        assert r2.data == b"hello-get:/two"
