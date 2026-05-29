"""Chrome 148 (stable as of May 2026) ClientHello fingerprint."""

from __future__ import annotations

from .._fingerprint import Fingerprint
from . import chrome_146 as _prev

#: Per-request HTTP headers Chrome 148 stable sends on a top-level navigation
#: from Linux, captured from a live incognito hit on tls.peet.ws.
HTTP_HEADERS: dict[str, str] = {
    "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Linux"',
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
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
    # TLS bytes are identical to chrome_146; only HTTP headers differ.
    # Round-trip through to_dict/from_dict so the two profiles stay
    # byte-locked at the TLS layer with no duplicated spec.
    spec = _prev.build().to_dict()
    spec["http_headers"] = HTTP_HEADERS
    return Fingerprint.from_dict(spec)
