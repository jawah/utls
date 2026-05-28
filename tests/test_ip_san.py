from __future__ import annotations

import socket
import ssl as _stdlib_ssl
import threading

import pytest
import trustme

import utls


def _serve_once(server_ctx: _stdlib_ssl.SSLContext) -> tuple[int, threading.Thread]:
    """Spawn a one-shot blocking TLS server on 127.0.0.1; return (port, thread)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _run():
        try:
            client, _ = srv.accept()
            try:
                tls = server_ctx.wrap_socket(client, server_side=True)
                try:
                    # Read whatever the client sends post-handshake (may be 0).
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
    return port, t


def _client_ctx_trusting(ca: trustme.CA) -> utls.SSLContext:
    ctx = utls.create_default_context()
    ctx.load_verify_locations(cadata=ca.cert_pem.bytes().decode("ascii"))
    return ctx


def test_ipv4_san_matches_when_server_hostname_is_ipv4_literal():
    """Positive case: cert SAN ``IP:127.0.0.1`` + server_hostname ``127.0.0.1``
    must verify successfully."""
    ca = trustme.CA()
    server_cert = ca.issue_cert("127.0.0.1")
    server_ctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_ctx)

    port, t = _serve_once(server_ctx)
    client_ctx = _client_ctx_trusting(ca)

    raw = socket.create_connection(("127.0.0.1", port))
    try:
        with client_ctx.wrap_socket(raw, server_hostname="127.0.0.1") as s:
            assert s.version().startswith("TLSv1.")
            # Confirm we actually matched against an IP SAN, not a DNS SAN.
            san = s.getpeercert()["subjectAltName"]
            assert ("IP Address", "127.0.0.1") in san
    finally:
        t.join(timeout=2)


def test_ipv4_san_mismatch_is_rejected():
    """Negative case: cert SAN ``IP:127.0.0.1`` + server_hostname
    ``127.0.0.2`` must raise ``SSLCertVerificationError`` (IP mismatch)."""
    ca = trustme.CA()
    # Cert is only valid for 127.0.0.1.
    server_cert = ca.issue_cert("127.0.0.1")
    server_ctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_ctx)

    port, t = _serve_once(server_ctx)
    client_ctx = _client_ctx_trusting(ca)

    raw = socket.create_connection(("127.0.0.1", port))
    try:
        with pytest.raises(utls.SSLCertVerificationError):
            client_ctx.wrap_socket(raw, server_hostname="127.0.0.2")
    finally:
        try:
            raw.close()
        except OSError:
            pass
        t.join(timeout=2)


def test_ipv6_san_matches_when_server_hostname_is_ipv6_literal():
    """Positive case for IPv6: cert SAN ``IP:::1`` + server_hostname ``::1``
    must verify. We connect over IPv4 (127.0.0.1) because the server bind
    is v4, but the *verification target* is the v6 literal - proving the
    string is parsed by ``X509_VERIFY_PARAM_set1_ip_asc`` and matched
    against the iPAddress SAN."""
    ca = trustme.CA()
    server_cert = ca.issue_cert("::1")
    server_ctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_ctx)

    port, t = _serve_once(server_ctx)
    client_ctx = _client_ctx_trusting(ca)

    raw = socket.create_connection(("127.0.0.1", port))
    try:
        # server_hostname is the v6 literal: routing must use IP-SAN, not DNS.
        with client_ctx.wrap_socket(raw, server_hostname="::1") as s:
            san = s.getpeercert()["subjectAltName"]
            ip_entries = [v for k, v in san if k == "IP Address"]
            assert ip_entries, f"no IP Address SAN: {san!r}"
    finally:
        t.join(timeout=2)


def test_dns_san_not_matched_by_ip_literal_server_hostname():
    """A cert with ONLY a dNSName SAN (``example.test``) must NOT validate
    when the caller passes an IP literal as ``server_hostname`` - the
    verifier must route to ``X509_check_ip``, which won't find a matching
    iPAddress SAN, and reject with cert-verify error."""
    ca = trustme.CA()
    server_cert = ca.issue_cert("example.test")  # DNS SAN only, no IP SAN.
    server_ctx = _stdlib_ssl.SSLContext(_stdlib_ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_ctx)

    port, t = _serve_once(server_ctx)
    client_ctx = _client_ctx_trusting(ca)

    raw = socket.create_connection(("127.0.0.1", port))
    try:
        with pytest.raises(utls.SSLCertVerificationError):
            client_ctx.wrap_socket(raw, server_hostname="127.0.0.1")
    finally:
        try:
            raw.close()
        except OSError:
            pass
        t.join(timeout=2)
