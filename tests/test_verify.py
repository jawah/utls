from __future__ import annotations

import pytest

import utls


def test_load_verify_locations_requires_an_argument():
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    with pytest.raises(utls.SSLError):
        ctx.load_verify_locations()


def test_load_default_certs_returns_without_error_on_supported_platform():
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    # On well-configured Linux/macOS hosts this succeeds; on minimal CI
    # containers without /etc/ssl/certs it may fail. We accept either as
    # long as the call doesn't crash the interpreter.
    try:
        ctx.load_default_certs()
    except utls.SSLError:
        pytest.skip("no system trust store available in this environment")


def test_cadata_pem_roundtrip(tmp_path):
    # Minimal self-signed cert generated offline; we just check that the
    # facade accepts PEM input and walks the BEGIN/END markers. A real
    # cert would be longer; the parser doesn't care about contents until
    # BoringSSL's d2i_X509 does.
    fake_pem = (
        b"-----BEGIN CERTIFICATE-----\n"
        b"MIIBkTCB+wIJAJxV9F0Q2YkBMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMMBHRl\n"
        b"-----END CERTIFICATE-----\n"
    )
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    # BoringSSL will reject this as a bogus cert (truncated DER); we just
    # want to confirm the PEM walker reaches the loader.
    with pytest.raises(utls.SSLError):
        ctx.load_verify_locations(cadata=fake_pem)


def test_cert_none_does_not_dress_protocol_errors_as_cert_failures():
    import socket
    import threading

    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    addr = lsock.getsockname()

    def serve():
        c, _ = lsock.accept()
        # Plain HTTP greeting - what a misconfigured HTTP proxy answers
        # to an HTTPS CONNECT attempt.
        c.send(b"HTTP/1.0 501 Not Implemented\r\nConnection: close\r\n\r\n")
        import time

        time.sleep(0.2)
        c.close()

    t = threading.Thread(target=serve)
    t.start()
    try:
        ctx = utls.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = utls.CERT_NONE
        raw = socket.create_connection(addr)
        with pytest.raises(utls.SSLError) as exc:
            ctx.wrap_socket(raw, server_hostname="localhost")
        # Must surface BoringSSL's diagnostic, not a fake cert failure.
        assert not isinstance(exc.value, utls.SSLCertVerificationError)
        msg = str(exc.value).lower()
        assert "wrong_version_number" in msg
        # Mirror urllib3-future's normalization (`_wrap_proxy_error`):
        # it collapses non-letters to spaces, so our underscore-separated
        # BoringSSL token must match "wrong version number".
        import re

        normalized = " ".join(re.split("[^a-z]", msg))
        assert "wrong version number" in normalized
    finally:
        lsock.close()
        t.join(timeout=5)
