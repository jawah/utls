"""PEM <-> DER helpers exposed by :mod:`utls._utils`.

The helpers exist so we can avoid pulling pyOpenSSL or cryptography into
the runtime dependency set. Tests here cover the conversion round-trip
and the two malformed-input rejection paths.
"""

from __future__ import annotations

import pytest

from utls._utils import DER_cert_to_PEM_cert, PEM_cert_to_DER_cert


def test_pem_der_round_trip():
    # A 64-byte payload exercises the base64 + header path past the
    # no-padding edge case.
    der = bytes(range(64))
    pem = DER_cert_to_PEM_cert(der)
    assert pem.startswith("-----BEGIN CERTIFICATE-----")
    assert pem.rstrip().endswith("-----END CERTIFICATE-----")
    assert PEM_cert_to_DER_cert(pem) == der


def test_pem_to_der_rejects_missing_header():
    with pytest.raises(ValueError, match="must start with"):
        PEM_cert_to_DER_cert("not a pem string")


def test_pem_to_der_rejects_missing_footer():
    bad = "-----BEGIN CERTIFICATE-----\nAAAA\n"
    with pytest.raises(ValueError, match="must end with"):
        PEM_cert_to_DER_cert(bad)
