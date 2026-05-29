from __future__ import annotations

import pytest

import utls
from utls.profiles import chrome_131, chrome_142, chrome_146, chrome_148, chrome_stable



@pytest.mark.parametrize("module", [chrome_131, chrome_142, chrome_146, chrome_148, chrome_stable])
def test_profile_exposes_http_headers(module):
    assert hasattr(module, "HTTP_HEADERS"), \
        f"{module.__name__} missing HTTP_HEADERS constant"
    assert isinstance(module.HTTP_HEADERS, dict)
    assert module.HTTP_HEADERS, "HTTP_HEADERS must not be empty"


@pytest.mark.parametrize("module", [chrome_131, chrome_142, chrome_146, chrome_148])
def test_profile_headers_include_chrome_essentials(module):
    """The minimum set every Chrome-impersonation header bundle must carry."""
    h = module.HTTP_HEADERS
    for required in (
        "User-Agent",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "Accept",
        "Accept-Encoding",
        "Accept-Language",
        "Sec-Fetch-Site",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Dest",
        "Upgrade-Insecure-Requests",
    ):
        assert required in h, f"{module.__name__} HTTP_HEADERS missing {required!r}"


@pytest.mark.parametrize("module,version_token", [
    (chrome_131, "131"),
    (chrome_142, "142"),
    (chrome_146, "146"),
    (chrome_148, "148"),
])
def test_profile_headers_version_tokens_match_profile(module, version_token):
    """User-Agent and sec-ch-ua must reflect the profile's Chrome major."""
    h = module.HTTP_HEADERS
    assert f"Chrome/{version_token}" in h["User-Agent"]
    assert f'"Chromium";v="{version_token}"' in h["sec-ch-ua"]


def test_profile_headers_excluded_keys_absent():
    """The intentionally-excluded headers must not appear; they are request-
    or session-dependent and belong to the HTTP-layer caller."""
    for h in (chrome_131.HTTP_HEADERS, chrome_142.HTTP_HEADERS, chrome_146.HTTP_HEADERS, chrome_148.HTTP_HEADERS):
        for forbidden in (
            "Cookie", "Referer", "Host",
            "Content-Length", "Content-Type",
        ):
            assert forbidden not in h, (
                f"{forbidden!r} should not be in a profile HTTP_HEADERS dict - "
                "it is request- or session-dependent"
            )


def test_profile_headers_preserve_wire_order():
    """Order in the dict must match Chrome's on-the-wire order. The order is
    itself a fingerprintable signal even though HTTP/2 HPACK doesn't require
    it for correctness.

    Chrome's documented order has sec-ch-ua before User-Agent, and
    sec-fetch-* between Accept and Accept-Encoding.
    """
    keys = list(chrome_142.HTTP_HEADERS.keys())
    # Spot-check a couple of ordering invariants rather than encode the full
    # sequence here (which would duplicate the profile constant).
    assert keys.index("sec-ch-ua") < keys.index("User-Agent")
    assert keys.index("Accept") < keys.index("Sec-Fetch-Site")
    assert keys.index("Sec-Fetch-Dest") < keys.index("Accept-Encoding")
    assert keys.index("Accept-Encoding") < keys.index("Accept-Language")
    # RFC 9218 Priority is the trailing header on Chrome 124+ navigations.
    assert keys[-1] == "Priority"
    assert chrome_142.HTTP_HEADERS["Priority"] == "u=0, i"
    assert chrome_131.HTTP_HEADERS["Priority"] == "u=0, i"


def test_chrome_stable_aliases_current_chrome_headers():
    """``chrome:stable`` must alias the most recent shipping profile -
    bump this expectation in lockstep with ``chrome_stable.py`` when a new
    Chrome stable lands."""
    assert chrome_stable.HTTP_HEADERS is chrome_148.HTTP_HEADERS



def test_fingerprint_carries_headers_through_build():
    fp = chrome_142.build()
    headers = fp.http_headers
    assert headers == chrome_142.HTTP_HEADERS
    # Order must round-trip exactly.
    assert list(headers.keys()) == list(chrome_142.HTTP_HEADERS.keys())


def test_fingerprint_http_headers_returns_copy():
    """Mutating the returned dict must not affect the profile."""
    fp = chrome_142.build()
    h1 = fp.http_headers
    h1["User-Agent"] = "evil"
    h1["X-New"] = "x"
    # Fresh read = pristine.
    h2 = fp.http_headers
    assert h2["User-Agent"] != "evil"
    assert "X-New" not in h2
    # Profile constant itself untouched.
    assert "evil" not in chrome_142.HTTP_HEADERS.get("User-Agent", "")


def test_fingerprint_from_capture_has_empty_headers():
    """A Fingerprint reconstructed from a captured ClientHello has no profile
    and therefore no headers - must not raise, must return an empty dict."""
    # A minimal but valid TLS 1.3 ClientHello captured from a real Chrome run
    # is what `from_capture` expects; for this test we just exercise the
    # empty-headers contract by going through `_wrap` directly, which is the
    # path `from_capture` uses.
    handle = chrome_131.build()._handle
    bare = utls.Fingerprint._wrap(handle)
    assert bare.http_headers == {}



def test_accessor_raises_before_set_fingerprint():
    ctx = utls.create_default_context()
    with pytest.raises(ValueError, match="no fingerprint set"):
        ctx.http_header_for_fingerprint()


def test_accessor_returns_headers_after_set_by_name():
    ctx = utls.create_default_context()
    ctx.set_fingerprint("chrome:142")
    assert ctx.http_header_for_fingerprint() == chrome_142.HTTP_HEADERS


def test_accessor_returns_headers_after_set_by_object():
    ctx = utls.create_default_context()
    fp = chrome_131.build()
    ctx.set_fingerprint(fp)
    assert ctx.http_header_for_fingerprint() == chrome_131.HTTP_HEADERS


def test_accessor_clears_on_set_fingerprint_none():
    ctx = utls.create_default_context()
    ctx.set_fingerprint("chrome:142")
    ctx.set_fingerprint(None)
    with pytest.raises(ValueError, match="no fingerprint set"):
        ctx.http_header_for_fingerprint()


def test_accessor_tracks_replacement():
    """Setting a new fingerprint replaces the header bundle."""
    ctx = utls.create_default_context()
    ctx.set_fingerprint("chrome:131")
    assert "131" in ctx.http_header_for_fingerprint()["User-Agent"]
    ctx.set_fingerprint("chrome:142")
    assert "142" in ctx.http_header_for_fingerprint()["User-Agent"]


def test_accessor_returns_copy_not_live_view():
    """Mutating the dict returned by the accessor must not affect future
    reads from the same context."""
    ctx = utls.create_default_context()
    ctx.set_fingerprint("chrome:142")
    h = ctx.http_header_for_fingerprint()
    h["User-Agent"] = "tampered"
    assert ctx.http_header_for_fingerprint()["User-Agent"] != "tampered"


def test_accessor_survives_ech_fork():
    """`set_ech_configs` clones the context; the cloned context must
    keep the same fingerprint headers."""
    ctx = utls.create_default_context()
    ctx.set_fingerprint("chrome:142")
    forked = ctx.set_ech_configs(None)
    assert forked.http_header_for_fingerprint() == chrome_142.HTTP_HEADERS
