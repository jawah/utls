"""Numeric values for protocol/verify constants are chosen to match CPython's
:mod:`ssl` module exactly, so ``utls.CERT_REQUIRED == ssl.CERT_REQUIRED``
and ``utls.PROTOCOL_TLS_CLIENT == ssl.PROTOCOL_TLS_CLIENT``. The Python
facade enforces the symbolic constants; the Rust side only accepts the
client variant.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Final

from . import _utls as _core

# Value matches ssl.PROTOCOL_TLS_CLIENT
PROTOCOL_TLS_CLIENT: Final[int] = 16
# Value matches ssl.PROTOCOL_TLS_SERVER (CPython hard-codes 17). utls supports
# server-side TLS for everything BoringSSL still exposes (mTLS, ALPN
# selection, SNI dispatch, ECDH curve restriction, session ticket count,
# session_id_context); features BoringSSL deleted (compression, SSLv2/v3)
# are explicitly rejected.
PROTOCOL_TLS_SERVER: Final[int] = 17
# stdlib alias: ``PROTOCOL_TLS`` is the deprecated catch-all (value ``2``).
# Constructing an SSLContext with it defaults to client-side TLS. Some
# third-party code still references this; we accept it for parity.
PROTOCOL_TLS: Final[int] = 2
# Even older alias - identical to PROTOCOL_TLS by stdlib convention.
PROTOCOL_SSLv23: Final[int] = PROTOCOL_TLS
# Deprecated per-version selectors. Stdlib still exports them and tolerates them
PROTOCOL_TLSv1: Final[int] = 3
PROTOCOL_TLSv1_1: Final[int] = 4
PROTOCOL_TLSv1_2: Final[int] = 5


CERT_NONE: Final[int] = 0
CERT_OPTIONAL: Final[int] = 1
CERT_REQUIRED: Final[int] = 2


class TLSVersion(enum.IntEnum):
    """Mirrors :class:`ssl.TLSVersion`."""

    MINIMUM_SUPPORTED = -2
    SSLv3 = 0x0300
    TLSv1 = 0x0301
    TLSv1_1 = 0x0302
    TLSv1_2 = 0x0303
    TLSv1_3 = 0x0304
    MAXIMUM_SUPPORTED = -1


class Purpose(enum.Enum):
    """Mirrors :class:`ssl.Purpose` (the subset that affects trust loading)."""

    SERVER_AUTH = 0
    CLIENT_AUTH = 1


class Options(enum.IntFlag):
    """Mirrors :class:`ssl.Options`."""

    OP_NO_SSLv2 = 0x01000000
    OP_NO_SSLv3 = 0x02000000
    OP_NO_TLSv1 = 0x04000000
    OP_NO_TLSv1_1 = 0x10000000
    OP_NO_TLSv1_2 = 0x08000000
    OP_NO_TLSv1_3 = 0x20000000
    # Honored: BoringSSL never compresses.
    OP_NO_COMPRESSION = 0x00020000
    # Honored: BoringSSL refuses client-side renegotiation unconditionally.
    OP_NO_RENEGOTIATION = 0x40000000
    # Stored verbatim: SSL_OP_NO_TICKET only affects the server side; on a
    # client it's a no-op. Accepted for API parity with ``ssl.OP_NO_TICKET``.
    OP_NO_TICKET = 0x00004000

    def __contains__(self, other: object) -> bool:
        # Permissive membership: any int with the right bits set counts.
        # Without this, ``utls.OP_NO_TLSv1_3 in ctx.options`` would raise
        # ``TypeError`` on Python 3.12+ if either operand were a plain int.
        if isinstance(other, int):
            return (int(self) & int(other)) == int(other)
        return NotImplemented  # Defensive: mimic stdlib's fallback path.


OP_NO_SSLv2: Final[Options] = Options.OP_NO_SSLv2
OP_NO_SSLv3: Final[Options] = Options.OP_NO_SSLv3
OP_NO_TLSv1: Final[Options] = Options.OP_NO_TLSv1
OP_NO_TLSv1_1: Final[Options] = Options.OP_NO_TLSv1_1
OP_NO_TLSv1_2: Final[Options] = Options.OP_NO_TLSv1_2
OP_NO_TLSv1_3: Final[Options] = Options.OP_NO_TLSv1_3
OP_NO_COMPRESSION: Final[Options] = Options.OP_NO_COMPRESSION
OP_NO_RENEGOTIATION: Final[Options] = Options.OP_NO_RENEGOTIATION
OP_NO_TICKET: Final[Options] = Options.OP_NO_TICKET

HAS_TLSv1_3: Final[bool] = True
HAS_ALPN: Final[bool] = True
# Matches stdlib's ``ssl.HAS_NEVER_CHECK_COMMON_NAME``: indicates the
# verifier can be told to skip CN fallback. utls does so unconditionally
# (``X509_CHECK_FLAG_NEVER_CHECK_SUBJECT``).
HAS_NEVER_CHECK_COMMON_NAME: Final[bool] = True

VERIFY_DEFAULT: Final[int] = 0
VERIFY_CRL_CHECK_LEAF: Final[int] = 0x4
VERIFY_CRL_CHECK_CHAIN: Final[int] = 0x4 | 0x8
VERIFY_X509_STRICT: Final[int] = 0x20
VERIFY_X509_TRUSTED_FIRST: Final[int] = 0x8000
VERIFY_ALLOW_PROXY_CERTS: Final[int] = 0x40
VERIFY_X509_PARTIAL_CHAIN: Final[int] = 0x80000

OPENSSL_VERSION: Final[str] = _core.BORINGSSL_VERSION
# Tuple shape matches CPython's (major, minor, fix, patch, status) but we
# encode an utls-specific version string in the last field for clarity.
OPENSSL_VERSION_INFO: Final[tuple[int, int, int, int, int]] = (0, 0, 0, 0, 0)
# Numeric form. BoringSSL doesn't publish a stable OpenSSL-shaped version
# number; report ``0`` (the same value urllib3 sees when stdlib is built
# against a non-OpenSSL backend). Downstream code that gates behavior on
# this number should sniff :data:`OPENSSL_VERSION` for the ``"utls"`` token
# instead.
OPENSSL_VERSION_NUMBER: Final[int] = 0
