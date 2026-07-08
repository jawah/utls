"""Chrome 150 (stable as of July 2026) ClientHello fingerprint."""

from __future__ import annotations

from .._fingerprint import Fingerprint
from . import chrome_148 as _prev
from ._base import SigAlg

HTTP_HEADERS: dict[str, str] = {
    "sec-ch-ua": '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Linux"',
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
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

#: Chrome 150 signature_algorithms changed!
SIGNATURE_ALGORITHMS: list[int] = [
    SigAlg.mldsa44,
    SigAlg.mldsa65,
    SigAlg.mldsa87,
    SigAlg.ecdsa_secp256r1_sha256,
    SigAlg.rsa_pss_rsae_sha256,
    SigAlg.rsa_pkcs1_sha256,
    SigAlg.ecdsa_secp384r1_sha384,
    SigAlg.rsa_pss_rsae_sha384,
    SigAlg.rsa_pkcs1_sha384,
    SigAlg.rsa_pss_rsae_sha512,
    SigAlg.rsa_pkcs1_sha512,
]


def build() -> Fingerprint:
    spec = _prev.build().to_dict()
    spec["signature_algorithms"] = [int(s) for s in SIGNATURE_ALGORITHMS]
    spec["http_headers"] = HTTP_HEADERS
    return Fingerprint.from_dict(spec)
