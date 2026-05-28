
from __future__ import annotations

import pytest

import utls
from utls.profiles._base import Ext, Group


def test_all_presets_resolve():
    names = utls.presets()
    assert "chrome:131" in names
    assert "chrome:stable" in names
    # utls is Chrome-only by design.
    assert all(n.startswith("chrome:") for n in names), names
    for name in names:
        fp = utls.get_preset(name)
        assert isinstance(fp, utls.Fingerprint), name


def test_chrome_131_shape():
    fp = utls.get_preset("chrome:131")
    d = fp.to_dict()
    assert d["alpn"] == ["h2", "http/1.1"]
    assert d["alps"] == ["h2"]
    assert d["grease"] is True
    assert d["compress_certificate"] == ["brotli"]
    # X25519MLKEM768 first
    assert d["supported_groups"][0] == int(Group.X25519MLKEM768)
    # contains the canonical Chrome extension set
    exts = d["extensions_order"]
    for required in [
        int(Ext.server_name), int(Ext.supported_groups),
        int(Ext.application_layer_protocol_negotiation),
        int(Ext.key_share), int(Ext.supported_versions),
    ]:
        assert required in exts


def test_ja3_and_ja4_hashes_are_stable_and_nonempty():
    fp = utls.get_preset("chrome:131")
    j3 = fp.ja3_hash
    j4 = fp.ja4_hash
    assert isinstance(j3, str) and len(j3) == 32  # MD5 hex
    assert isinstance(j4, str) and len(j4) > 0
    # idempotent
    assert fp.ja3_hash == j3
    assert fp.ja4_hash == j4


def test_unknown_preset_raises():
    with pytest.raises(ValueError, match="unknown preset"):
        utls.get_preset("ie:6")


def test_ja4_pin_matches_rust():
    from utls import _utls
    assert _utls.JA4_SPEC_VERSION == utls.JA4_SPEC_VERSION == "0.18.8"


@pytest.mark.parametrize(
    "name,expected_ja4",
    [
        ("chrome:131", "t13d1516h2_8daaf6152771_02713d6af862"),
        ("chrome:142", "t13d1516h2_8daaf6152771_d8a2da3f94cd"),
        ("chrome:146", "t13d1516h2_8daaf6152771_d8a2da3f94cd"),
        ("chrome:148", "t13d1516h2_8daaf6152771_d8a2da3f94cd"),
        ("chrome:stable", "t13d1516h2_8daaf6152771_d8a2da3f94cd"),
    ],
)
def test_ja4_matches_real_chrome_capture(name: str, expected_ja4: str) -> None:
    fp = utls.get_preset(name)
    assert fp.ja4_hash == expected_ja4, (
        f"{name} JA4 drifted from captured ground truth; "
        "if Chrome shipped a real fingerprint change re-capture from "
        "tls.peet.ws and update the pinned value, otherwise this is a "
        "regression in the profile spec or fingerprint emitter."
    )
