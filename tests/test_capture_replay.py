from __future__ import annotations

import pytest

import utls


def _build_minimal_client_hello() -> bytes:
    """Hand-craft a ClientHello with one cipher, SNI + ALPN extensions."""
    # server_name (0): hostname "x.test"
    host = b"x.test"
    sni_inner = bytes([0]) + len(host).to_bytes(2, "big") + host
    sni_list = len(sni_inner).to_bytes(2, "big") + sni_inner
    sni = (0).to_bytes(2, "big") + len(sni_list).to_bytes(2, "big") + sni_list
    # ALPN (16): h2
    alpn_proto = b"\x02h2"
    alpn_list = len(alpn_proto).to_bytes(2, "big") + alpn_proto
    alpn = (16).to_bytes(2, "big") + len(alpn_list).to_bytes(2, "big") + alpn_list
    # supported_versions (43): TLS 1.3
    sv_body = b"\x02\x03\x04"
    sv = (43).to_bytes(2, "big") + len(sv_body).to_bytes(2, "big") + sv_body
    extensions = sni + alpn + sv
    ext_block = len(extensions).to_bytes(2, "big") + extensions

    legacy_version = b"\x03\x03"
    random = b"\x00" * 32
    session_id = b"\x00"
    cipher_suites = b"\x00\x02\x13\x01"  # one suite: TLS_AES_128_GCM_SHA256
    compression = b"\x01\x00"
    body = legacy_version + random + session_id + cipher_suites + compression + ext_block

    hs = bytes([0x01]) + len(body).to_bytes(3, "big") + body

    record = bytes([0x16]) + b"\x03\x01" + len(hs).to_bytes(2, "big") + hs
    return record


def test_capture_extracts_basic_shape():
    raw = _build_minimal_client_hello()
    fp = utls.Fingerprint.from_capture(raw)
    d = fp.to_dict()
    assert d["cipher_suites"] == [0x1301]
    assert d["alpn"] == ["h2"]
    assert 43 in d["extensions_order"]  # supported_versions
    assert 0 in d["extensions_order"]   # server_name
    assert 16 in d["extensions_order"]  # alpn


def test_capture_rejects_truncated_record():
    with pytest.raises(ValueError):
        utls.Fingerprint.from_capture(b"\x16\x03\x01")


def test_capture_rejects_non_handshake_record():
    with pytest.raises(ValueError):
        utls.Fingerprint.from_capture(b"\x17\x03\x03\x00\x05hello")
