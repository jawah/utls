"""Chrome 152 (stable as of August 2026) ClientHello fingerprint."""

from __future__ import annotations

from .._fingerprint import Fingerprint
from . import chrome_150 as _prev
from ._base import Ext

HTTP_HEADERS: dict[str, str] = {
    "sec-ch-ua": '"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Linux"',
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
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

#: Chrome Root Store trust-anchor IDs captured from Chrome 152 against
#: ``tls.peet.ws``. The TLS extension body is a 2-byte length prefix plus
#: this blob; BoringSSL's ``SSL_set1_requested_trust_anchors`` wants the
#: blob (concatenated 8-bit length-prefixed IDs).
TRUST_ANCHOR_IDS: bytes = bytes.fromhex(
    "08839a648c9b2d0107"
    "08839a648c9b2d010d"
    "0582df13020e"
    "0582df130201"
    "0582df13020d"
    "08839a648c9b2d010a"
    "0582df130214"
    "08839a648c9b2d010b"
    "04d679090b"
    "04d6790905"
    "04d6790908"
    "04d679090a"
    "08839a648c9b2d0112"
    "04d6790907"
    "04d6790901"
    "0582df130213"
    "0582df130206"
    "04d679090d"
    "08839a648c9b2d0113"
    "04d679090f"
    "08839a648c9b2d0108"
    "04d6790904"
    "0582df13020f"
    "04d6790906"
    "08839a648c9b2d010c"
    "08839a648c9b2d0109"
    "0582df130212"
    "04d679090c"
)
if len(TRUST_ANCHOR_IDS) != 0xB8:
    raise RuntimeError(
        f"Chrome 152 trust-anchor blob length {len(TRUST_ANCHOR_IDS)} != 184"
    )


def build() -> Fingerprint:
    spec = _prev.build().to_dict()
    grease = int(Ext.GREASE)
    trust = int(Ext.trust_anchors)
    order = [
        int(cp)
        for cp in spec["extensions_order"]
        if int(cp) not in (grease, trust)
    ]
    order.append(trust)
    order.append(grease)
    spec["extensions_order"] = order
    spec["trust_anchors"] = TRUST_ANCHOR_IDS
    # Chrome 152 prepends a per-connection GREASE value to signature_algorithms.
    spec["grease_sigalgs"] = True
    spec["http_headers"] = HTTP_HEADERS
    return Fingerprint.from_dict(spec)
