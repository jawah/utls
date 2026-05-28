"""Chrome 146 (stable as of Nov 2025) ClientHello fingerprint."""

from __future__ import annotations

from .._fingerprint import Fingerprint
from ._base import Ext, Group, SigAlg

#: Per-request HTTP headers Chrome 146 stable sends on a top-level navigation
#: from macOS, captured from a live curl-cffi 0.15 ``chrome146`` impersonation.
#: Insertion order is the on-the-wire order observed in the H2 HEADERS frame.
HTTP_HEADERS: dict[str, str] = {
    "sec-ch-ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
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
    "Priority": "u=0, i",
}


def build() -> Fingerprint:
    return Fingerprint(
        cipher_suites=[
            0x1301,
            0x1302,
            0x1303,
            0xC02B,
            0xC02F,
            0xC02C,
            0xC030,
            0xCCA9,
            0xCCA8,
            0xC013,
            0xC014,
            0x009C,
            0x009D,
            0x002F,
            0x0035,
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
        ech=True,
        padding=None,
        http_headers=HTTP_HEADERS,
    )
