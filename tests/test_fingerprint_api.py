"""Fingerprint API surface: dict round-trips, repr, cache behaviour.

Profile-specific assertions live in :mod:`tests.test_fingerprint_chrome`
and :mod:`tests.test_fingerprint_headers`; this file only exercises the
generic public API.
"""

from __future__ import annotations

import utls
from utls import Fingerprint, SSLContext


def test_from_dict_round_trips_ech_grease():
    # Chrome presets ship ech="grease" by default; the round-trip
    # must preserve that.
    fp = Fingerprint.from_preset("chrome:131")
    d = fp.to_dict()
    assert d["ech"] == "grease"
    fp2 = Fingerprint.from_dict(d)
    assert fp2.to_dict()["ech"] == "grease"


def test_from_dict_round_trips_ech_bytes():
    # The bytes-ECH branch fires for real ECHConfigList blobs.
    d = Fingerprint.from_preset("chrome:131").to_dict()
    d["ech"] = b"\x00\x01\x02\x03fake-ech-config"
    fp = Fingerprint.from_dict(d)
    out = fp.to_dict()["ech"]
    assert isinstance(out, (bytes, bytearray))
    assert bytes(out) == b"\x00\x01\x02\x03fake-ech-config"


def test_from_dict_round_trips_ech_off():
    d = Fingerprint.from_preset("chrome:131").to_dict()
    d["ech"] = "off"
    assert Fingerprint.from_dict(d).to_dict()["ech"] == "off"


def test_from_dict_round_trips_trust_anchors():
    blob = bytes.fromhex("01aa04d679090b")
    d = Fingerprint.from_preset("chrome:152").to_dict()
    d["trust_anchors"] = blob
    fp = Fingerprint.from_dict(d)
    assert fp.to_dict()["trust_anchors"] == blob
    d["trust_anchors"] = None
    assert Fingerprint.from_dict(d).to_dict()["trust_anchors"] is None


def test_repr_summarises_shape():
    fp = Fingerprint.from_preset("chrome:131")
    r = repr(fp)
    assert r.startswith("Fingerprint(")
    assert "ciphers=" in r
    assert "exts=" in r
    assert "alpn=" in r


def test_context_fingerprint_getter_falls_back_to_core_handle():
    # The Python-side cache (`_fp_py`) carries the original wrapper so
    # callers see the HTTP-header bundle on subsequent reads. When the
    # cache is empty (e.g. after an ECH-driven context clone that fails
    # to forward the cache), the getter must reconstruct a fingerprint
    # view from the live Rust handle.
    ctx = SSLContext(utls.PROTOCOL_TLS_CLIENT)
    ctx.set_fingerprint("chrome:131")
    assert ctx.fingerprint is not None
    ctx._fp_py = None
    fp2 = ctx.fingerprint
    assert fp2 is not None
    # Reconstructed view has no header bundle, but the TLS shape must
    # match the preset we installed.
    preset = Fingerprint.from_preset("chrome:131").to_dict()["cipher_suites"]
    assert fp2.to_dict()["cipher_suites"] == preset
