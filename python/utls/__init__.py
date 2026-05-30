"""
utls - Impersonator TLS for Python.

Drop-in for the client-side subset of the stdlib :mod:`ssl` module, backed by
BoringSSL via the :mod:`_utls` Rust extension, with first-class TLS
fingerprint impersonation. Please don't abuse this.
"""

from __future__ import annotations

#
# PEM<->DER ASCII armor codecs - backported from rtls, faster than the
# stdlib equivalents and dependency-free. Re-exported here so callers can
# substitute ``import utls as ssl`` without losing them.
from ssl import VerifyMode  # noqa: E402

from . import _utls as _core  # noqa: F401
from ._facade import (
    Certificate,
    MemoryBIO,
    SSLContext,
    SSLObject,
    SSLSession,
    create_default_context,
)
from ._fingerprint import JA4_SPEC_VERSION, Fingerprint
from ._socket import SSLSocket
from ._utils import DER_cert_to_PEM_cert, PEM_cert_to_DER_cert  # noqa: E402
from .constants import (
    CERT_NONE,
    CERT_OPTIONAL,
    CERT_REQUIRED,
    HAS_ALPN,
    HAS_NEVER_CHECK_COMMON_NAME,
    OP_NO_COMPRESSION,
    OP_NO_RENEGOTIATION,
    OP_NO_TICKET,
    OPENSSL_VERSION,
    OPENSSL_VERSION_INFO,
    OPENSSL_VERSION_NUMBER,
    PROTOCOL_TLS,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    VERIFY_ALLOW_PROXY_CERTS,
    VERIFY_CRL_CHECK_CHAIN,
    VERIFY_CRL_CHECK_LEAF,
    VERIFY_DEFAULT,
    VERIFY_X509_PARTIAL_CHAIN,
    VERIFY_X509_STRICT,
    VERIFY_X509_TRUSTED_FIRST,
    HAS_TLSv1_3,
    OP_NO_SSLv2,
    OP_NO_SSLv3,
    OP_NO_TLSv1,
    OP_NO_TLSv1_1,
    OP_NO_TLSv1_2,
    OP_NO_TLSv1_3,
    Options,
    PROTOCOL_SSLv23,
    PROTOCOL_TLSv1,
    PROTOCOL_TLSv1_1,
    PROTOCOL_TLSv1_2,
    Purpose,
    TLSVersion,
)
from .exceptions import (
    CertificateError,
    SSLCertVerificationError,
    SSLEOFError,
    SSLError,
    SSLSyscallError,
    SSLWantReadError,
    SSLWantWriteError,
    SSLZeroReturnError,
)
from .profiles import get as _get_profile
from .profiles import names as _profile_names

__all__ = [
    # ssl-shaped types
    "SSLContext",
    "SSLObject",
    "SSLSocket",
    "MemoryBIO",
    "SSLSession",
    "Certificate",
    "create_default_context",
    # constants
    "PROTOCOL_SSLv23",
    "PROTOCOL_TLS",
    "PROTOCOL_TLS_CLIENT",
    "PROTOCOL_TLS_SERVER",
    "PROTOCOL_TLSv1",
    "PROTOCOL_TLSv1_1",
    "PROTOCOL_TLSv1_2",
    "CERT_NONE",
    "CERT_OPTIONAL",
    "CERT_REQUIRED",
    "TLSVersion",
    "Purpose",
    "VerifyMode",
    "Options",
    "HAS_ALPN",
    "HAS_TLSv1_3",
    "HAS_NEVER_CHECK_COMMON_NAME",
    "OPENSSL_VERSION",
    "OPENSSL_VERSION_INFO",
    "OPENSSL_VERSION_NUMBER",
    "OP_NO_COMPRESSION",
    "OP_NO_RENEGOTIATION",
    "OP_NO_TICKET",
    "OP_NO_SSLv2",
    "OP_NO_SSLv3",
    "OP_NO_TLSv1",
    "OP_NO_TLSv1_1",
    "OP_NO_TLSv1_2",
    "OP_NO_TLSv1_3",
    "VERIFY_DEFAULT",
    "VERIFY_CRL_CHECK_LEAF",
    "VERIFY_CRL_CHECK_CHAIN",
    "VERIFY_X509_STRICT",
    "VERIFY_X509_TRUSTED_FIRST",
    "VERIFY_X509_PARTIAL_CHAIN",
    "VERIFY_ALLOW_PROXY_CERTS",
    # codec helpers (re-exported from stdlib for drop-in compat)
    "DER_cert_to_PEM_cert",
    "PEM_cert_to_DER_cert",
    # exceptions
    "SSLError",
    "SSLWantReadError",
    "SSLWantWriteError",
    "SSLEOFError",
    "SSLZeroReturnError",
    "SSLSyscallError",
    "SSLCertVerificationError",
    "CertificateError",
    # fingerprint
    "Fingerprint",
    "JA4_SPEC_VERSION",
    "presets",
    "get_preset",
    # misc
    "__version__",
]

__version__ = "2026.5.30"


def presets() -> list[str]:
    """Return all known fingerprint preset names (sorted)."""
    return _profile_names()


def get_preset(name: str) -> Fingerprint:
    """Look up a fingerprint preset by name (e.g. ``"chrome:131"``)."""
    return _get_profile(name)
