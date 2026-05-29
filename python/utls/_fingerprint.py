from __future__ import annotations

from typing import Any, Iterable, Mapping

from . import _utls as _core

#: Pinned JA4 spec revision (see FoxIO-LLC/ja4). Mirrored in
#: ``crates/utls-core/src/fingerprint/ja4.rs::JA4_SPEC_VERSION``.
#: Bumping is a minor-version bump for utls; CI asserts the two are equal.
JA4_SPEC_VERSION: str = "0.18.8"

# Sanity check at import time: if the Rust side disagrees we want a loud
# error, not a silent skew.
if _core.JA4_SPEC_VERSION != JA4_SPEC_VERSION:  # Defensive: dev-only assert.
    raise RuntimeError(
        f"JA4 spec version mismatch: utls Python = {JA4_SPEC_VERSION!r}, "
        f"utls Rust = {_core.JA4_SPEC_VERSION!r}. This build is inconsistent."
    )


class Fingerprint:
    """A declarative TLS ClientHello specification.

    Construct with keyword arguments to assemble a custom fingerprint, or use
    :meth:`from_preset` to pull one from the bundled profile registry.

    All sequence arguments are accepted as any iterable; they are normalized
    to ``list`` and validated on construction.
    """

    __slots__ = ("_handle", "_http_headers")

    # JA3/JA4 fields are accepted for ergonomic parity with other libraries
    # but are *advisory only* - they're hashes, not specs. We currently
    # raise NotImplementedError when used because we don't have a JA3/JA4
    # -> fingerprint *constructor* (the spec round-trip is lossy, by design).
    def __init__(
        self,
        *,
        ja3: str | None = None,
        ja4: str | None = None,
        cipher_suites: Iterable[int] | None = None,
        extensions_order: Iterable[int] | None = None,
        supported_groups: Iterable[int] | None = None,
        key_shares: Iterable[int] | None = None,
        signature_algorithms: Iterable[int] | None = None,
        alpn: Iterable[str] | None = None,
        alps: Iterable[str] | None = None,
        alps_use_new_codepoint: bool = True,
        record_size_limit: int | None = None,
        compress_certificate: Iterable[str] | None = None,
        grease: bool = True,
        ech: bool | bytes = False,
        padding: int | None = None,
        http_headers: Mapping[str, str] | None = None,
    ) -> None:
        if ja3 is not None or ja4 is not None:
            # We refuse to silently fabricate an unspecified ClientHello from
            # a hash. Document the limitation rather than ship a lie.
            raise NotImplementedError(
                "Constructing a Fingerprint from a JA3 or JA4 hash is not "
                "supported: a hash does not contain enough information to "
                "reproduce the original ClientHello. Use Fingerprint.from_preset() "
                "or Fingerprint.from_capture(raw_client_hello) instead."
            )
        self._handle = _core.Fingerprint(
            cipher_suites=list(cipher_suites or ()),
            extensions_order=list(extensions_order or ()),
            supported_groups=list(supported_groups or ()),
            key_shares=list(key_shares or ()),
            signature_algorithms=list(signature_algorithms or ()),
            alpn=list(alpn or ()),
            alps=list(alps or ()),
            alps_use_new_codepoint=alps_use_new_codepoint,
            compress_certificate=list(compress_certificate or ()),
            record_size_limit=record_size_limit,
            grease=grease,
            ech=ech,
            padding=padding,
        )
        # Static, per-request browser headers paired with this TLS profile.
        # Kept as plain data on the Python wrapper - it is never seen by the
        # Rust core (TLS-layer only), but travels with the fingerprint so
        # downstream HTTP libraries can pull a coherent (TLS + headers) bundle
        # from a single source. We copy on store and copy on read so callers
        # cannot mutate the profile through the live dict.
        self._http_headers: dict[str, str] = dict(http_headers) if http_headers else {}

    @classmethod
    def from_preset(cls, name: str) -> Fingerprint:
        """Look up a fingerprint by preset name (e.g. ``"chrome:131"``)."""
        from .profiles import get as _get_profile

        return _get_profile(name)

    @classmethod
    def from_capture(cls, raw_client_hello: bytes) -> Fingerprint:
        """Parse a captured ClientHello (TLS record) into a Fingerprint."""
        handle = _core.Fingerprint.from_capture(raw_client_hello)
        return cls._wrap(handle)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Fingerprint:
        """Inverse of :meth:`to_dict`."""
        # `ech` round-trips as 'off'/'grease'/bytes; normalize.
        ech_raw = data.get("ech", "off")
        if isinstance(ech_raw, (bytes, bytearray)):
            ech: bool | bytes = bytes(ech_raw)
        elif ech_raw == "grease":
            ech = True
        else:
            ech = False
        return cls(
            cipher_suites=data.get("cipher_suites"),
            extensions_order=data.get("extensions_order"),
            supported_groups=data.get("supported_groups"),
            key_shares=data.get("key_shares"),
            signature_algorithms=data.get("signature_algorithms"),
            alpn=data.get("alpn"),
            alps=data.get("alps"),
            alps_use_new_codepoint=bool(data.get("alps_use_new_codepoint", True)),
            compress_certificate=data.get("compress_certificate"),
            record_size_limit=data.get("record_size_limit"),
            grease=bool(data.get("grease", True)),
            ech=ech,
            padding=data.get("padding"),
            http_headers=data.get("http_headers"),
        )

    @classmethod
    def _wrap(cls, handle: Any) -> Fingerprint:
        # Internal: build a Fingerprint around an existing Rust handle without
        # going through the validating constructor. Used by `from_capture`,
        # which has no profile and therefore no headers to attach.
        obj = object.__new__(cls)
        obj._handle = handle
        obj._http_headers = {}
        return obj

    def to_dict(self) -> dict[str, Any]:
        d = dict(self._handle.to_dict())
        if self._http_headers:
            d["http_headers"] = dict(self._http_headers)
        return d

    @property
    def http_headers(self) -> dict[str, str]:
        """Static HTTP request headers paired with this fingerprint.

        Returns a fresh ``dict`` (copy) preserving the insertion order Chrome
        sends on the wire - relevant for full impersonation since the header
        sequence is itself a fingerprintable signal even though HTTP/2 HPACK
        does not require it for correctness.

        Empty for fingerprints built from :meth:`from_capture` (no profile
        context) or for hand-built fingerprints that didn't pass
        ``http_headers=``.

        These are the *every-request*, non-method-specific browser headers
        (``User-Agent``, ``sec-ch-ua*``, ``Accept``, ``Accept-Encoding``,
        ``Accept-Language``, ``sec-fetch-*``, ``Upgrade-Insecure-Requests``).
        ``Cookie``, ``Referer``, ``Host``, and ``Content-*`` are excluded
        because they are request-, session-, or body-dependent and must be
        owned by the caller.
        """
        return dict(self._http_headers)

    @property
    def ja3_hash(self) -> str:
        return self._handle.ja3_hash()

    @property
    def ja3_string(self) -> str:
        return self._handle.ja3_string()

    @property
    def ja4_hash(self) -> str:
        return self._handle.ja4_hash()

    def __repr__(self) -> str:
        d = self.to_dict()
        return (
            f"Fingerprint(ciphers={len(d['cipher_suites'])}, "
            f"exts={len(d['extensions_order'])}, alpn={d['alpn']}, "
            f"ja3={self.ja3_hash[:8]}..., ja4={self.ja4_hash[:16]}...)"
        )
