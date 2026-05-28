from __future__ import annotations

import pytest
import trustme

import utls
from utls import SSLContext, SSLError
from utls._utils import PEM_cert_to_DER_cert


def test_default_certs_load_server_auth():
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    ctx.load_default_certs(utls.Purpose.SERVER_AUTH)


def test_default_certs_load_default_purpose():
    ctx = utls.SSLContext(utls.PROTOCOL_TLS_CLIENT)
    ctx.load_default_certs()


# load_verify_locations: malformed PEM rejection

def test_load_verify_locations_rejects_pem_without_end_marker():
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    bad = b"-----BEGIN CERTIFICATE-----\nAAAA\n(no end marker here)\n"
    with pytest.raises(SSLError, match="BEGIN without matching END"):
        ctx.load_verify_locations(cadata=bad)


def test_load_verify_locations_rejects_invalid_pem_base64():
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    bad = (
        b"-----BEGIN CERTIFICATE-----\n"
        b"@@@not-base64@@@\n"
        b"-----END CERTIFICATE-----\n"
    )
    with pytest.raises(SSLError, match="malformed PEM body"):
        ctx.load_verify_locations(cadata=bad)


def test_load_verify_locations_accepts_raw_der_bytes():
    # No BEGIN banner -> takes the raw-DER branch of _load_cadata.
    ca = trustme.CA()
    der = PEM_cert_to_DER_cert(ca.cert_pem.bytes().decode("ascii"))
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    before = ctx.cert_store_stats()["x509"]
    ctx.load_verify_locations(cadata=der)
    assert ctx.cert_store_stats()["x509"] == before + 1


def test_create_default_context_with_cadata():
    # When cadata is provided, the context must use it instead of
    # falling back to the OS trust store.
    ca = trustme.CA()
    pem = ca.cert_pem.bytes()
    ctx = utls.create_default_context(cadata=pem)
    assert ctx.cert_store_stats()["x509"] >= 1


# get_ca_certs decoder-missing fallback

def test_get_ca_certs_falls_back_to_empty_dicts_when_decoder_missing():
    # When the core lacks decode_cert_der (older builds, future trims),
    # get_ca_certs must still honour the list-length contract by
    # returning one empty dict per stored DER.
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)

    class _CtxProxy:
        def __init__(self, real, ders):
            self._real = real
            self._ders = ders

        def ca_certs_der(self):
            return self._ders

        def __getattr__(self, name):
            if name == "decode_cert_der":
                raise AttributeError(name)
            return getattr(self._real, name)

    ctx._ctx = _CtxProxy(ctx._ctx, [b"\x30\x82\x00\x01", b"\x30\x82\x00\x02"])
    assert ctx.get_ca_certs(binary_form=False) == [{}, {}]
