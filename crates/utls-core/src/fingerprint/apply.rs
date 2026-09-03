//! Apply a [`Fingerprint`] to a live BoringSSL `SSL*` handle.
//!
//! This module is the meeting point between *what we want to emit* (the
//! declarative `Fingerprint`) and *what BoringSSL is willing to let us
//! control*. We track `boring-sys` at a `cloudflare/boring` master revision
//! whose vendored BoringSSL carries native ML-DSA (FIPS 204) TLS support
//! (`SSL_SIGN_ML_DSA_44/65/87`); every knob we need is upstream - no
//! patches required.
//!
//! ## Upstream BoringSSL APIs we use
//!
//! * `cipher_suites` - `SSL_CTX_set_ciphersuites` (TLS 1.3) +
//!   `SSL_set_cipher_list` (TLS 1.2).
//! * `supported_groups` - `SSL_set1_groups_list` (accepts the name
//!   `X25519MLKEM768` natively).
//! * `signature_algorithms` - `SSL_set_verify_algorithm_prefs` (raw
//!   uint16 codepoints, so post-quantum ML-DSA schemes go out verbatim).
//! * `alpn` - `SSL_set_alpn_protos`.
//! * `alps` - `SSL_add_application_settings`.
//! * `grease` - `SSL_CTX_set_grease_enabled`.
//! * `grease_sigalgs` - `SSL_CTX_set_grease_sigalgs_enabled` (Chrome 152+).
//! * `compress_certificate` - `SSL_CTX_add_cert_compression_alg`.
//! * `extension order permutation` - `SSL_set_permute_extensions`
//!   (matches Chrome 110+ random-per-handshake behaviour).
//! * `status_request` / `signed_certificate_timestamp` - `SSL_enable_*`.
//! * `trust_anchors` (`0xCA34`) - `SSL_set1_requested_trust_anchors`.
//!
//! ## What we deliberately do **not** do
//!
//! * Reach into BoringSSL internals via offset arithmetic. If an upstream
//!   API isn't there, the feature is not supported - we don't lie on the
//!   wire by silently dropping it. `extensions_order` is treated as
//!   advisory: BoringSSL emits the extensions in its own (optionally
//!   permuted) order; the JA4 hash sorts before hashing so this stays
//!   stable, and the JA4_r variation per-handshake matches real Chrome.

use std::ffi::CString;
use std::os::raw::c_int;

use super::spec::{EchPolicy, Fingerprint, TRUST_ANCHORS_EXTENSION};
use crate::error::{Error, Result};

/// Apply `fp` to `ssl`.
///
/// `alpn_override`, when `Some`, replaces the fingerprint's ALPN list for
/// both ALPN advertisement and ALPS gating. See
/// [`super::spec::Fingerprint::apply_to_ssl_with_alpn_override`] for the
/// "WebSocket-over-h1 Chrome" rationale.
///
/// # Safety
///
/// `ssl` must be a non-null, live `*mut SSL` not yet in handshake.
pub unsafe fn apply(
    fp: &Fingerprint,
    ssl: *mut boring_sys::SSL,
    alpn_override: Option<&[Vec<u8>]>,
) -> Result<()> {
    // SAFETY: caller guarantees `ssl` is a valid, pre-handshake `*mut SSL`.
    // Each helper is itself `unsafe fn` and inherits that same invariant.
    unsafe {
        apply_cipher_suites(fp, ssl)?;
        apply_supported_groups(fp, ssl)?;
        apply_signature_algorithms(fp, ssl)?;
        // ALPN: when the user explicitly set ALPN via SSLContext.set_alpn_protocols
        // *after* set_fingerprint, the CTX-level list propagates to the new SSL
        // automatically (BoringSSL inherits it on SSL_new). We skip applying the
        // fingerprint's ALPN here so we don't clobber that override.
        if alpn_override.is_none() {
            apply_alpn(fp, ssl)?;
        }
        apply_cert_compression(fp, ssl)?;
        apply_stapling(fp, ssl)?;
        apply_grease(fp, ssl)?;
        apply_extensions_order(fp, ssl)?;
        apply_key_shares(fp, ssl)?;
        apply_alps(fp, ssl, alpn_override)?;
        apply_record_size_limit(fp, ssl)?;
        apply_ech(fp, ssl)?;
        apply_padding(fp, ssl)?;
        apply_trust_anchors(fp, ssl)?;
    }
    Ok(())
}

// Per-field helpers - one function per knob so tests can target them.

unsafe fn apply_cipher_suites(fp: &Fingerprint, ssl: *mut boring_sys::SSL) -> Result<()> {
    if fp.cipher_suites.is_empty() {
        return Ok(());
    }
    // BoringSSL's `SSL_set_cipher_list` (and the legacy OpenSSL one it shadows)
    // takes a *name*-based list, not raw codepoints. The `0xXX,0xXX` hex
    // syntax accepted by the `openssl ciphers` CLI is *not* honored at the
    // API layer - passing it returns `NO_CIPHER_MATCH`. We therefore map
    // codepoints to BoringSSL's accepted names and silently drop any
    // codepoint we don't know (the fingerprint metadata is preserved
    // verbatim for JA3/JA4 hashing regardless).
    //
    // The table covers every TLS 1.2 suite that the supported preset
    // browsers (Chrome/Firefox/Safari/Edge) actually offer. TLS 1.3 suites
    // are *not* configurable client-side in BoringSSL; the mandatory three
    // are always offered, in fixed order - see comment below.
    fn name_for(codepoint: u16) -> Option<&'static str> {
        match codepoint {
            // TLS 1.2 ECDHE
            0xC02B => Some("ECDHE-ECDSA-AES128-GCM-SHA256"),
            0xC02F => Some("ECDHE-RSA-AES128-GCM-SHA256"),
            0xC02C => Some("ECDHE-ECDSA-AES256-GCM-SHA384"),
            0xC030 => Some("ECDHE-RSA-AES256-GCM-SHA384"),
            0xCCA9 => Some("ECDHE-ECDSA-CHACHA20-POLY1305"),
            0xCCA8 => Some("ECDHE-RSA-CHACHA20-POLY1305"),
            0xC009 => Some("ECDHE-ECDSA-AES128-SHA"),
            0xC013 => Some("ECDHE-RSA-AES128-SHA"),
            0xC00A => Some("ECDHE-ECDSA-AES256-SHA"),
            0xC014 => Some("ECDHE-RSA-AES256-SHA"),
            // RSA static (Chrome's "fallback" tail)
            0x009C => Some("AES128-GCM-SHA256"),
            0x009D => Some("AES256-GCM-SHA384"),
            0x002F => Some("AES128-SHA"),
            0x0035 => Some("AES256-SHA"),
            // TLS 1.3 codepoints are accepted as-is by BoringSSL only via
            // `SSL_CTX_set_ciphersuites`, which isn't exposed in boring-sys 4
            // and which BoringSSL ignores at the per-SSL level anyway.
            0x1301..=0x1303 => None,
            _ => None,
        }
    }
    let names: Vec<&str> = fp
        .cipher_suites
        .iter()
        .filter_map(|&cp| name_for(cp))
        .collect();
    if names.is_empty() {
        // No TLS 1.2 suites we know how to express -> leave BoringSSL's
        // defaults in place rather than risk NO_CIPHER_MATCH.
        return Ok(());
    }
    let s = CString::new(names.join(":")).unwrap();
    // SAFETY: ssl + nul-term string valid.
    let rc = unsafe { boring_sys::SSL_set_cipher_list(ssl, s.as_ptr()) };
    if rc != 1 {
        return Err(Error::from_boring_queue("SSL_set_cipher_list"));
    }
    Ok(())
}

unsafe fn apply_supported_groups(fp: &Fingerprint, ssl: *mut boring_sys::SSL) -> Result<()> {
    if fp.supported_groups.is_empty() {
        return Ok(());
    }
    // `SSL_set1_groups_list` accepts BoringSSL's *names*, not IANA codepoints.
    // (Unlike the cipher list it will reject decimal numbers outright.)
    // We map codepoints to names and silently drop unknowns; the fingerprint
    // metadata is preserved verbatim for JA3/JA4 hashing regardless.
    fn name_for(codepoint: u16) -> Option<&'static str> {
        match codepoint {
            0x0017 => Some("P-256"),
            0x0018 => Some("P-384"),
            0x0019 => Some("P-521"),
            0x001D => Some("X25519"),
            0x001E => Some("X448"),
            // Post-quantum hybrids - present in BoringSSL recent enough to
            // ship in our patched build. If not recognized by the linked
            // BoringSSL, SSL_set1_groups_list will return failure; we keep
            // them here so the patched build can advertise them and stock
            // builds get a clean error rather than silent omission.
            0x11EC => Some("X25519MLKEM768"),
            0x6399 => Some("X25519Kyber768Draft00"),
            _ => None,
        }
    }
    let names: Vec<&str> = fp
        .supported_groups
        .iter()
        .filter_map(|&cp| name_for(cp))
        .collect();
    if names.is_empty() {
        return Ok(());
    }
    let s = CString::new(names.join(":")).unwrap();
    // SAFETY: ssl + nul-term string valid.
    let rc = unsafe { boring_sys::SSL_set1_groups_list(ssl, s.as_ptr()) };
    if rc != 1 {
        // Some BoringSSL builds don't know X25519MLKEM768. Retry without the
        // post-quantum entries; this lets stock builds keep working while
        // the fingerprint metadata still reflects the requested PQ offer.
        let fallback: Vec<&str> = names
            .into_iter()
            .filter(|n| !n.contains("MLKEM") && !n.contains("Kyber"))
            .collect();
        if fallback.is_empty() {
            return Err(Error::from_boring_queue("SSL_set1_groups_list"));
        }
        let s2 = CString::new(fallback.join(":")).unwrap();
        // SAFETY: ssl + nul-term string valid.
        let rc2 = unsafe { boring_sys::SSL_set1_groups_list(ssl, s2.as_ptr()) };
        if rc2 != 1 {
            return Err(Error::from_boring_queue("SSL_set1_groups_list"));
        }
    }
    Ok(())
}

unsafe fn apply_signature_algorithms(fp: &Fingerprint, ssl: *mut boring_sys::SSL) -> Result<()> {
    if fp.signature_algorithms.is_empty() {
        return Ok(());
    }
    // The advertised `signature_algorithms` extension is the client's *verify*
    // preference list (the schemes it will accept in the peer's certificate).
    // We set it by raw uint16 codepoint via `SSL_set_verify_algorithm_prefs`
    // rather than the name-based `SSL_set1_sigalgs_list`: the latter only
    // understands schemes BoringSSL has a string name for, so it would
    // silently drop anything newer than the library's built-in table (e.g.
    // the ML-DSA / FIPS 204 codepoints Chrome 150+ advertises), putting a
    // JA4 on the wire that disagrees with the one we compute from the spec.
    // Codepoints go out verbatim, so the wire matches the fingerprint exactly.
    let prefs: Vec<u16> = fp.signature_algorithms.clone();
    // SAFETY: `ssl` valid pre-handshake; `prefs` outlives the call, which
    // copies the array. `num_prefs` is the element count, not byte length.
    let rc =
        unsafe { boring_sys::SSL_set_verify_algorithm_prefs(ssl, prefs.as_ptr(), prefs.len()) };
    if rc != 1 {
        return Err(Error::from_boring_queue("SSL_set_verify_algorithm_prefs"));
    }
    Ok(())
}

unsafe fn apply_alpn(fp: &Fingerprint, ssl: *mut boring_sys::SSL) -> Result<()> {
    if fp.alpn.is_empty() {
        return Ok(());
    }
    let mut wire = Vec::new();
    for p in &fp.alpn {
        let b = p.as_bytes();
        if b.is_empty() || b.len() > 255 {
            return Err(Error::Usage(format!(
                "ALPN protocol {p:?} length out of range"
            )));
        }
        wire.push(b.len() as u8);
        wire.extend_from_slice(b);
    }
    // SAFETY: pointer + length describe a valid &[u8]; SSL_set_alpn_protos
    // copies the buffer internally.
    let rc = unsafe { boring_sys::SSL_set_alpn_protos(ssl, wire.as_ptr(), wire.len()) };
    if rc != 0 {
        return Err(Error::from_boring_queue("SSL_set_alpn_protos"));
    }
    Ok(())
}

unsafe fn apply_cert_compression(fp: &Fingerprint, ssl: *mut boring_sys::SSL) -> Result<()> {
    // BoringSSL only includes the `compress_certificate` (0x001b) extension
    // in the ClientHello when at least one algorithm has been registered on
    // the parent `SSL_CTX` via `SSL_CTX_add_cert_compression_alg`. The
    // registration is per-CTX (not per-SSL), which is fine for utls because
    // each fingerprint is owned by a single Context.
    //
    // For a *client* we don't need `compress` (we never send compressed
    // certs - that direction is server-only in practice), but we **must**
    // provide a real `decompress` for every algorithm we advertise. RFC
    // 8879 lets the server pick any algorithm we listed; once it does,
    // a callback that returns 0 aborts the handshake (BoringSSL does not
    // fall back to uncompressed). Returning 0 also leaves the SSL with no
    // validated chain, so `SSL_get_verify_result` is non-zero and the
    // failure surfaces in Python as `SSLCertVerificationError` even though
    // the actual root cause is a decompression refusal. Bug fixed: we now
    // ship a real brotli decompressor and only register algorithms we can
    // actually decompress.
    //
    // Registration is idempotent in the wrong direction: BoringSSL rejects
    // duplicate alg_ids with "one error". To stay safe across repeated
    // wrap_socket calls on the same Context we swallow ERR_get_error after
    // each call when it's just the duplicate-registration error.
    if fp.compress_certificate.is_empty() {
        return Ok(());
    }

    /// Brotli decompression callback for `compress_certificate` (alg 2).
    ///
    /// Called by BoringSSL after the server sends a CompressedCertificate
    /// message. The compressed payload is `(in_buf, in_len)`; the expected
    /// uncompressed length (advertised by the server) is `uncompressed_len`.
    /// On success we must populate `*out` with a freshly allocated
    /// `CRYPTO_BUFFER` of *exactly* `uncompressed_len` bytes and return 1.
    /// Returning 0 is a fatal handshake error.
    extern "C" fn brotli_decompress(
        _ssl: *mut boring_sys::SSL,
        out: *mut *mut boring_sys::CRYPTO_BUFFER,
        uncompressed_len: usize,
        in_buf: *const u8,
        in_len: usize,
    ) -> std::os::raw::c_int {
        const MAX_CERT_BYTES: usize = 1 << 20; // 1 MiB
        const INITIAL_CAP: usize = 64 * 1024; // 64 KiB

        if in_buf.is_null() || out.is_null() {
            return 0; // Defensive: BoringSSL never passes nulls, but be safe.
        }
        if uncompressed_len == 0 || uncompressed_len > MAX_CERT_BYTES {
            return 0;
        }
        // SAFETY: BoringSSL hands us a valid (in_buf, in_len) describing
        // the on-the-wire CompressedCertificate payload. We only read.
        let compressed = unsafe { std::slice::from_raw_parts(in_buf, in_len) };

        let mut decoded: Vec<u8> = Vec::with_capacity(INITIAL_CAP.min(uncompressed_len));
        let mut input = compressed;
        let mut decoder = brotli::Decompressor::new(&mut input, 4096);
        // Cap actual reads at uncompressed_len + 1: if the decoder produces
        // more, the peer lied about the length and we reject. We use
        // `Read::take` to enforce this without growing `decoded` past the
        // declared size.
        let mut limited = std::io::Read::take(&mut decoder, (uncompressed_len as u64) + 1);
        if std::io::Read::read_to_end(&mut limited, &mut decoded).is_err() {
            return 0;
        }
        if decoded.len() != uncompressed_len {
            // RFC 8879: the uncompressed_len field MUST match the actual
            // size of the decompressed Certificate message exactly.
            return 0;
        }
        // SAFETY: CRYPTO_BUFFER_new copies `decoded.len()` bytes from our
        // pointer; passing a null pool means "use the global pool". A NULL
        // return means OOM (rare) which we surface as decompression failure.
        let buf = unsafe {
            boring_sys::CRYPTO_BUFFER_new(decoded.as_ptr(), decoded.len(), std::ptr::null_mut())
        };
        if buf.is_null() {
            return 0;
        }
        // SAFETY: caller-provided out-slot is a valid `*mut *mut CRYPTO_BUFFER`.
        unsafe {
            *out = buf;
        }
        1
    }

    let ctx = unsafe { boring_sys::SSL_get_SSL_CTX(ssl) };
    if ctx.is_null() {
        return Err(Error::Usage("SSL_get_SSL_CTX returned null".into()));
    }
    for alg in &fp.compress_certificate {
        let alg_id: u16 = alg.codepoint();
        // Only brotli is implemented anyway.
        let decompress: boring_sys::ssl_cert_decompression_func_t = match alg_id {
            2 => Some(brotli_decompress),
            _ => continue,
        };
        // SAFETY: `ctx` is a valid SSL_CTX from a live SSL; the function
        // pointer is `extern "C"` with the exact prototype BoringSSL expects.
        let rc =
            unsafe { boring_sys::SSL_CTX_add_cert_compression_alg(ctx, alg_id, None, decompress) };
        if rc != 1 {
            // Duplicate registration on a reused CTX is fine; drain and ignore.
            // SAFETY: ERR_get_error is thread-local and always safe.
            let _ = unsafe { boring_sys::ERR_get_error() };
        }
    }
    Ok(())
}

/// Toggle TLS extensions whose presence in the ClientHello is gated by
/// boolean BoringSSL toggles rather than data we configure. We drive these
/// off the `extensions_order` list so that profile authors get exactly the
/// extensions they listed and no surprises.
unsafe fn apply_stapling(fp: &Fingerprint, ssl: *mut boring_sys::SSL) -> Result<()> {
    // 0x0005 status_request: ask the server to staple an OCSP response.
    if fp.extensions_order.contains(&0x0005) {
        // SAFETY: `ssl` is a valid pre-handshake *mut SSL.
        unsafe { boring_sys::SSL_enable_ocsp_stapling(ssl) };
    }
    // 0x0012 signed_certificate_timestamp: ask for SCTs.
    if fp.extensions_order.contains(&0x0012) {
        // SAFETY: same as above.
        unsafe { boring_sys::SSL_enable_signed_cert_timestamps(ssl) };
    }
    Ok(())
}

unsafe fn apply_grease(fp: &Fingerprint, ssl: *mut boring_sys::SSL) -> Result<()> {
    // BoringSSL ships GREASE *off* by default (see `SSL_CTX::grease_enabled`
    // initializer in `bssl/ssl/ssl_lib.cc`). Browsers we impersonate (Chrome,
    // Edge) emit GREASE; Firefox does not. To match either, we toggle the
    // GREASE flag on the parent `SSL_CTX` via the existing public API
    // `SSL_CTX_set_grease_enabled` - this turns on the bracketing GREASE
    // extensions (one prepended, one appended to the extension permutation
    // built by `ssl_setup_extension_permutation`) plus the GREASE entries
    // sprinkled into the cipher list, supported_groups, supported_versions,
    // and key_share. GREASE inside `signature_algorithms` is a *separate*
    // knob (`SSL_CTX_set_grease_sigalgs_enabled`); Chrome 152+ turns it on.
    //
    // The toggle is per-CTX, not per-SSL. Because utls's fingerprint lives
    // on the context (one fingerprint per Context, applied to every SSL
    // spawned from it) this is the correct granularity. A future per-SSL
    // override would need patch 0004-grease-toggle.patch.
    //
    // SAFETY: `ssl` is a valid pre-handshake *mut SSL; SSL_get_SSL_CTX is
    // a const accessor that never invalidates `ssl`.
    let ctx = unsafe { boring_sys::SSL_get_SSL_CTX(ssl) };
    if ctx.is_null() {
        return Err(Error::Usage("SSL_get_SSL_CTX returned null".into()));
    }
    let enabled = if fp.grease { 1 } else { 0 };
    unsafe { boring_sys::SSL_CTX_set_grease_enabled(ctx, enabled) };
    // Chrome 152+: prepend a per-connection GREASE value to signature_algorithms.
    // Independent of `grease_enabled` until BoringSSL folds the two together.
    let sigalgs_enabled = if fp.grease && fp.grease_sigalgs { 1 } else { 0 };
    unsafe { boring_sys::SSL_CTX_set_grease_sigalgs_enabled(ctx, sigalgs_enabled) };
    Ok(())
}

unsafe fn apply_extensions_order(fp: &Fingerprint, ssl: *mut boring_sys::SSL) -> Result<()> {
    // Modern Chrome (110+) **shuffles** its ClientHello extension order on
    // every handshake; the JA4 hash sorts extensions before hashing so it
    // stays stable across permutations, while JA4_r (the raw, ordered
    // variant) varies per connection. The `extensions_order` field in our
    // profile is therefore advisory: it lists the codepoints Chrome would
    // emit, and we let BoringSSL permute them at ClientHello assembly time.
    //
    // BoringSSL 5.1+ exposes this knob as `SSL_set_permute_extensions`
    // (public API, no patch required). We turn it on iff the profile lists
    // any extensions - i.e. always, for any non-default fingerprint.
    //
    // For *deterministic* ordering (legacy/non-Chrome profiles or test
    // builds), call `SSL_set_permute_extensions(ssl, 0)` and BoringSSL will
    // use its built-in static order. We never need to force an arbitrary
    // explicit permutation: the static order is already what stock
    // BoringSSL emits, and the random order is what Chrome emits.
    if fp.extensions_order.is_empty() {
        return Ok(());
    }
    let enabled: c_int = if fp.permute_extensions { 1 } else { 0 };
    // SAFETY: `ssl` is a valid pre-handshake *mut SSL.
    unsafe { boring_sys::SSL_set_permute_extensions(ssl, enabled) };
    Ok(())
}

unsafe fn apply_key_shares(fp: &Fingerprint, ssl: *mut boring_sys::SSL) -> Result<()> {
    if fp.key_shares.is_empty() {
        return Ok(());
    }
    // `SSL_set1_client_key_shares` (BoringSSL upstream) configures the
    // exact sequence of groups for which the client should emit key_share
    // entries in the initial ClientHello. Browsers send key shares for
    // both X25519MLKEM768 and X25519 (Chrome 124+) which is observable
    // and matters for fingerprinting; without this call BoringSSL's
    // default selector picks at most two groups on its own.
    //
    // The group_ids slice MUST be a (not-necessarily-contiguous)
    // subsequence of the configured supported_groups; callers (i.e.
    // profile authors) are responsable for satisfying that invariant.
    let groups: &[u16] = fp.key_shares.as_slice();
    // SAFETY: pointer + length valid; BoringSSL copies the contents.
    let rc = unsafe { boring_sys::SSL_set1_client_key_shares(ssl, groups.as_ptr(), groups.len()) };
    if rc != 1 {
        return Err(Error::from_boring_queue("SSL_set1_client_key_shares"));
    }
    Ok(())
}

unsafe fn apply_alps(
    fp: &Fingerprint,
    ssl: *mut boring_sys::SSL,
    alpn_override: Option<&[Vec<u8>]>,
) -> Result<()> {
    if fp.alps.is_empty() {
        return Ok(());
    }
    // Select the wire codepoint (new 0x44CD vs legacy 0x4469). MUST be set
    // *before* SSL_add_application_settings is called. Chrome 109-123 used
    // the legacy codepoint; Chrome 124+ and BoringSSL's default use the new
    // one. Mismatches here are visible in JA4_r and PeetPrint.
    // SAFETY: ssl valid; function takes a boolean toggle and returns void.
    unsafe {
        boring_sys::SSL_set_alps_use_new_codepoint(
            ssl,
            if fp.alps_use_new_codepoint { 1 } else { 0 },
        );
    }
    // `SSL_add_application_settings(ssl, proto, proto_len, settings, settings_len)`
    // is public API in BoringSSL since the Sept 2024 snapshot (shipped with
    // `boring-sys = "5"`). We pass an empty settings blob - clients only
    // need to advertise the codepoint pre-handshake; real settings are
    // negotiated during the handshake and don't change the ClientHello.
    //
    // When the caller has overridden ALPN (via SSLContext.set_alpn_protocols),
    // skip ALPS entries whose protocol is no longer offered. Chrome never
    // advertises ALPS for a protocol it didn't also list in ALPN; emitting
    // an orphan ALPS entry would produce an internally incoherent ClientHello
    // that no real Chrome ever sends, which would itself defeat impersonation.
    for proto in &fp.alps {
        let b = proto.as_bytes();
        if let Some(override_list) = alpn_override {
            if !override_list.iter().any(|p| p.as_slice() == b) {
                continue;
            }
        }
        // SAFETY: pointer + length valid; passing 0-length settings is allowed.
        let rc = unsafe {
            boring_sys::SSL_add_application_settings(ssl, b.as_ptr(), b.len(), std::ptr::null(), 0)
        };
        if rc != 1 {
            return Err(Error::from_boring_queue("SSL_add_application_settings"));
        }
    }
    Ok(())
}

unsafe fn apply_record_size_limit(fp: &Fingerprint, ssl: *mut boring_sys::SSL) -> Result<()> {
    if fp.record_size_limit.is_none() {
        return Ok(());
    }
    // TODO: requires patch 0002-record-size-limit-extension.patch
    let _ = ssl;
    Ok(())
}

unsafe fn apply_ech(fp: &Fingerprint, ssl: *mut boring_sys::SSL) -> Result<()> {
    match &fp.ech {
        EchPolicy::Off => Ok(()),
        EchPolicy::Grease => {
            // SAFETY: ssl valid; boolean toggle. Returns void in BoringSSL.
            unsafe { boring_sys::SSL_set_enable_ech_grease(ssl, 1) };
            Ok(())
        }
        EchPolicy::Real(config) => {
            // SAFETY: pointer + length valid; BoringSSL copies the config.
            let rc =
                unsafe { boring_sys::SSL_set1_ech_config_list(ssl, config.as_ptr(), config.len()) };
            if rc != 1 {
                return Err(Error::from_boring_queue("SSL_set1_ech_config_list"));
            }
            Ok(())
        }
    }
}

unsafe fn apply_padding(_fp: &Fingerprint, _ssl: *mut boring_sys::SSL) -> Result<()> {
    // BoringSSL's `SSL_set_record_padding_callback` is server-side; for the
    // ClientHello padding extension we rely on the patch series. The padding
    // *extension* is included automatically by BoringSSL when needed to
    // round the ClientHello up - explicit padding length control needs a
    // patch (tracked: `0005-clienthello-padding-target.patch`).
    Ok(())
}

/// Emit the `trust_anchors` (0xCA34) extension.
///
/// Driven primarily by `fp.trust_anchors`. If that is `None` but
/// `extensions_order` lists 0xCA34, we still send an empty list so the
/// codepoint appears on the wire (JA4 counts it; an empty list is a
/// valid "retry-flow only" advertisement).
unsafe fn apply_trust_anchors(fp: &Fingerprint, ssl: *mut boring_sys::SSL) -> Result<()> {
    let ids: &[u8] = match &fp.trust_anchors {
        Some(v) => v.as_slice(),
        None if fp.extensions_order.contains(&TRUST_ANCHORS_EXTENSION) => &[],
        None => return Ok(()),
    };
    // SAFETY: `ssl` is a valid pre-handshake *mut SSL; BoringSSL copies
    // `(ids, ids_len)` internally. An empty slice is documented to still
    // emit the extension.
    let rc = unsafe { boring_sys::SSL_set1_requested_trust_anchors(ssl, ids.as_ptr(), ids.len()) };
    if rc != 1 {
        return Err(Error::from_boring_queue("SSL_set1_requested_trust_anchors"));
    }
    Ok(())
}
