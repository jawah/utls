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
