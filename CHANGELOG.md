Release History
===============

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
