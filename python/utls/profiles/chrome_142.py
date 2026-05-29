"""Chrome 142 (stable as of Oct 2025) ClientHello fingerprint."""

from __future__ import annotations

from .._fingerprint import Fingerprint
from ._base import Ext, Group, SigAlg

#: Static, per-request HTTP headers Chrome 142 sends on a top-level navigation.
#: Identical shape to :data:`utls.profiles.chrome_131.HTTP_HEADERS`; only the
#: version-bearing strings (``sec-ch-ua``, ``User-Agent``) change. See the
#: ``chrome_131`` module docstring for the contract (which headers are
#: included, which are deliberately omitted, why insertion order matters).
HTTP_HEADERS: dict[str, str] = {
    "sec-ch-ua": '"Google Chrome";v="142", "Chromium";v="142", "Not?A_Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
    # RFC 9218 Extensible Priorities. ``u=0`` = urgency 0 (highest, used
    # for top-level navigations); ``i`` = incremental.
    "Priority": "u=0, i",
}


def build() -> Fingerprint:
    return Fingerprint(
        cipher_suites=[
            # TLS 1.3
            0x1301,  # TLS_AES_128_GCM_SHA256
            0x1302,  # TLS_AES_256_GCM_SHA384
            0x1303,  # TLS_CHACHA20_POLY1305_SHA256
            # TLS 1.2 ECDHE
            0xC02B,  # ECDHE-ECDSA-AES128-GCM-SHA256
            0xC02F,  # ECDHE-RSA-AES128-GCM-SHA256
            0xC02C,  # ECDHE-ECDSA-AES256-GCM-SHA384
            0xC030,  # ECDHE-RSA-AES256-GCM-SHA384
            0xCCA9,  # ECDHE-ECDSA-CHACHA20-POLY1305
            0xCCA8,  # ECDHE-RSA-CHACHA20-POLY1305
            0xC013,  # ECDHE-RSA-AES128-SHA
            0xC014,  # ECDHE-RSA-AES256-SHA
            # RSA fallback
            0x009C,  # AES128-GCM-SHA256
            0x009D,  # AES256-GCM-SHA384
            0x002F,  # AES128-SHA
            0x0035,  # AES256-SHA
        ],
        extensions_order=[
            Ext.server_name,
            Ext.extended_master_secret,
            Ext.renegotiation_info,
            Ext.supported_groups,
            Ext.ec_point_formats,
            Ext.session_ticket,
            Ext.application_layer_protocol_negotiation,
            Ext.status_request,
            Ext.signature_algorithms,
            Ext.signed_certificate_timestamp,
            Ext.key_share,
            Ext.psk_key_exchange_modes,
            Ext.supported_versions,
            Ext.compress_certificate,
            Ext.application_settings_new,
            Ext.encrypted_client_hello,
            Ext.GREASE,
        ],
        supported_groups=[
            Group.X25519MLKEM768,
            Group.X25519,
            Group.secp256r1,
            Group.secp384r1,
        ],
        # Browsers send key shares for the top two groups: post-quantum first,
        # then classical X25519. Wired via SSL_set1_client_key_shares.
        key_shares=[Group.X25519MLKEM768, Group.X25519],
        signature_algorithms=[
            SigAlg.ecdsa_secp256r1_sha256,
            SigAlg.rsa_pss_rsae_sha256,
            SigAlg.rsa_pkcs1_sha256,
            SigAlg.ecdsa_secp384r1_sha384,
            SigAlg.rsa_pss_rsae_sha384,
            SigAlg.rsa_pkcs1_sha384,
            SigAlg.rsa_pss_rsae_sha512,
            SigAlg.rsa_pkcs1_sha512,
        ],
        alpn=["h2", "http/1.1"],
        alps=["h2"],
        compress_certificate=["brotli"],
        grease=True,
        ech=True,  # Chrome 142 ships ECH GREASE on stable.
        padding=None,  # BoringSSL pads to the standard 512-byte boundary.
        http_headers=HTTP_HEADERS,
    )
