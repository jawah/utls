Release History
===============

2026.9.3
--------

- Added `chrome:152` profile and moved `chrome:stable` to it. Chrome 152
  is the first stable major to send the `trust_anchors` extension
  (`0xCA34`, draft-ietf-tls-trust-anchor-ids) with the Chrome Root Store
  ID list. Cipher suites, groups, and ML-DSA signature algorithms are
  unchanged from `chrome:150`; the extra extension changes the JA4 from
  `t13d1516h2_…` to `t13d1517h2_8daaf6152771_cb7bf5808d99`.
- `trust_anchors` is now a first-class Fingerprint field, applied via
  BoringSSL's `SSL_set1_requested_trust_anchors`.
- Chrome 152 also prepends a per-connection GREASE value to
  `signature_algorithms` (visible in PeetPrint, stripped from JA4).
  Wired via `SSL_CTX_set_grease_sigalgs_enabled`. Builds compile
  BoringSSL from `vendor/boringssl` because `cloudflare/boring`'s
  vendored snapshot still predates this API.

2026.7.8
--------

- Added `chrome:150` profile and moved `chrome:stable` to it. Chrome 150 is the first stable major to advertise post-quantum ML-DSA (FIPS 204) signature algorithms (`mldsa44`/`mldsa65`/`mldsa87`) in the `signature_algorithms` extension; this changes the TLS layer and the JA4 versus the 142/146/148 line.
- `signature_algorithms` are now emitted by raw codepoint via `SSL_set_verify_algorithm_prefs` instead of name-mapped through `SSL_set1_sigalgs_list`. The old path silently dropped any scheme BoringSSL had no string name for (e.g. ML-DSA), which would have put a JA4 on the wire that disagreed with the computed one.
- Pinned `boring-sys` to a `cloudflare/boring` master revision (post PR #509, BoringSSL `e2a57cfb4`) so the vendored BoringSSL understands the ML-DSA signature codepoints. crates.io `boring-sys` 5.1.0 predates ML-DSA.

2026.5.30
---------

- Fixed `set_fingerprint("chrome:*")` causing handshake failure against servers that honor cert compression.
- Fixed `set_alpn_protocols(...)` called after `set_fingerprint(...)` being silently ignored; the fingerprint's per-connection `SSL_set_alpn_protos` dismissed the user override.
- Fixed RSS climbing to the lifetime peak of buffered ciphertext.

2026.5.29
---------

- Fixed stop wrapping socket-level `OSError` (notably `socket.timeout`) as `SSLError`; matches stdlib and unbreaks HTTP-client retry logic.
- Fixed assign `ctx.minimum_version = ssl.TLSVersion.TLSv1_2` that raises `ValueError: 769 is not a valid TLSVersion`.
- Fixed inverted version sentinels (e.g. `ctx.minimum_version = MAXIMUM_SUPPORTED`) to the library default at the bound they apply to instead of raising `min > max`.
- Fixed option checks like `utls.OP_NO_TLSv1_3 in ctx.options`.
- `PROTOCOL_TLS_CLIENT` / `PROTOCOL_TLS_SERVER` now equal stdlib's wire values (`16` / `17`); `utls.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` no longer raises.
- Fixed missing protocol aliases: `PROTOCOL_SSLv23`, `PROTOCOL_TLSv1`, `PROTOCOL_TLSv1_1`, `PROTOCOL_TLSv1_2` for urllib3-future integration.
- Fixed `hostname_checks_common_name` to raise `AttributeError` on get/set; BoringSSL never falls back to CN, so the inherited stdlib toggle was misleading.
- Fixed `SSLSocket` to define `_io_refs` / `_decref_socketios` with stdlib's deferred-close semantics; `f = sock.makefile(); sock.close(); f.close()` no longer raises `AttributeError`.
- Fixed `SSLSocket.shutdown(how)` is now exposed as a TCP-level pass-through to the underlying socket.
- Fixed `SSLObject.read(len, buffer)` buffer-fill overload, used by `asyncio.sslproto._do_read__buffered` on Python 3.11+.
- Fixed handshake errors no longer get dressed up as `SSLCertVerificationError` when `verify_mode=CERT_NONE`; BoringSSL's diagnostic (e.g. `WRONG_VERSION_NUMBER`) is now surfaced verbatim so callers like urllib3-future can detect HTTP-served-as-HTTPS proxies.
- Fixed sdist to now include `LICENSE` and `NOTICE`.

2026.5.28
---------

- Initial release
