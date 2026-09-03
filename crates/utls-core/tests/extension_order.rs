//! ClientHello extension *permutation* test.
//!
//! As of `boring-sys = "5"` (BoringSSL snapshot Sept 2025+) we drive
//! extension ordering through stock `SSL_set_permute_extensions`. There
//! is no upstream API for forcing a specific permutation, and we don't
//! want to pretend we have one. This test instead asserts the two
//! contracts we *do* honor:
//!
//! 1. With `permute_extensions = true` (the default for Chrome-style
//!    profiles), the same fingerprint emits different extension orders
//!    across handshakes. JA4 (which sorts) stays stable, JA4_r varies.
//! 2. With `permute_extensions = false`, the order is deterministic
//!    across handshakes.
//!
//! In both modes the *set* of extensions emitted matches the set
//! BoringSSL knows about for the configured options (we don't assert
//! the exact set here; that's covered by the live JA4 probe in
//! `tests/test_handshake.py`).

use utls_core::context::{Context, Protocol, TlsVersion, VerifyMode};
use utls_core::fingerprint::spec::{Fingerprint, TRUST_ANCHORS_EXTENSION};

/// Strips the GREASE bracketing codepoints from a ClientHello extension
/// list so we can compare the "real" extension sequence across handshakes.
fn is_grease(cp: u16) -> bool {
    let lo = cp & 0xff;
    let hi = (cp >> 8) & 0xff;
    lo == hi && (lo & 0x0f) == 0x0a
}

/// Minimal ClientHello extension parser. Returns the codepoint sequence.
fn parse_ext_codepoints(record: &[u8]) -> Option<Vec<u16>> {
    if record.len() < 5 || record[0] != 22 {
        return None;
    }
    let frag_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let frag = record.get(5..5 + frag_len)?;
    if frag.len() < 4 || frag[0] != 1 {
        return None;
    }
    let body_len = ((frag[1] as usize) << 16) | ((frag[2] as usize) << 8) | (frag[3] as usize);
    let body = frag.get(4..4 + body_len)?;
    let mut o = 2 + 32;
    if body.len() <= o {
        return None;
    }
    let sid_len = body[o] as usize;
    o += 1 + sid_len;
    if body.len() < o + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
    o += 2 + cs_len;
    if body.len() <= o {
        return None;
    }
    let comp_len = body[o] as usize;
    o += 1 + comp_len;
    if body.len() < o + 2 {
        return None;
    }
    let ext_total = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
    o += 2;
    let end = o + ext_total;
    if end > body.len() {
        return None;
    }
    let mut out = Vec::new();
    while o < end {
        if o + 4 > end {
            return None;
        }
        let cp = u16::from_be_bytes([body[o], body[o + 1]]);
        let len = u16::from_be_bytes([body[o + 2], body[o + 3]]) as usize;
        o += 4;
        if o + len > end {
            return None;
        }
        out.push(cp);
        o += len;
    }
    Some(out)
}

/// Drive a handshake far enough to capture the ClientHello record.
fn capture_raw_client_hello(fp: Fingerprint) -> Vec<u8> {
    let ctx = Context::new(Protocol::TlsClient).expect("Context::new");
    ctx.set_verify_mode(VerifyMode::None)
        .expect("set_verify_mode");
    ctx.set_check_hostname(false).expect("set_check_hostname");
    ctx.set_version_bounds(TlsVersion::Tls1_2, TlsVersion::Tls1_3)
        .expect("set_version_bounds");
    let incoming = utls_core::bio::MemoryBio::new().expect("incoming BIO");
    let mut outgoing = utls_core::bio::MemoryBio::new().expect("outgoing BIO");
    ctx.set_fingerprint(Some(fp)).expect("set_fingerprint");
    let mut conn = ctx
        .wrap_bio(&incoming, &outgoing, Some("example.invalid"), None)
        .expect("wrap_bio");
    match conn.do_handshake() {
        Ok(_) => unreachable!("handshake cannot complete without a peer"),
        Err(utls_core::error::Error::WantRead) => {}
        Err(other) => panic!("unexpected handshake error: {other:?}"),
    }
    let buf = outgoing.read(None).expect("read ClientHello");
    assert!(!buf.is_empty(), "no ClientHello was written");
    buf
}

/// Drives a fresh ClientHello and returns its (non-GREASE) extension
/// codepoint sequence.
fn capture_client_hello(fp: Fingerprint) -> Vec<u16> {
    parse_ext_codepoints(&capture_raw_client_hello(fp))
        .expect("ClientHello did not parse")
        .into_iter()
        .filter(|cp| !is_grease(*cp))
        .collect()
}

/// First signature_algorithms codepoint on the wire, if the extension is present.
fn first_sigalg(record: &[u8]) -> Option<u16> {
    let exts = parse_ext_block(record)?;
    for (cp, body) in exts {
        if cp != 0x000d || body.len() < 4 {
            continue;
        }
        let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        if list_len < 2 || body.len() < 2 + list_len {
            return None;
        }
        return Some(u16::from_be_bytes([body[2], body[3]]));
    }
    None
}

fn parse_ext_block(record: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
    if record.len() < 5 || record[0] != 22 {
        return None;
    }
    let frag_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let frag = record.get(5..5 + frag_len)?;
    if frag.len() < 4 || frag[0] != 1 {
        return None;
    }
    let body_len = ((frag[1] as usize) << 16) | ((frag[2] as usize) << 8) | (frag[3] as usize);
    let body = frag.get(4..4 + body_len)?;
    let mut o = 2 + 32;
    let sid_len = *body.get(o)? as usize;
    o += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*body.get(o)?, *body.get(o + 1)?]) as usize;
    o += 2 + cs_len;
    let comp_len = *body.get(o)? as usize;
    o += 1 + comp_len;
    let ext_total = u16::from_be_bytes([*body.get(o)?, *body.get(o + 1)?]) as usize;
    o += 2;
    let end = o + ext_total;
    if end > body.len() {
        return None;
    }
    let mut out = Vec::new();
    while o < end {
        if o + 4 > end {
            return None;
        }
        let cp = u16::from_be_bytes([body[o], body[o + 1]]);
        let len = u16::from_be_bytes([body[o + 2], body[o + 3]]) as usize;
        o += 4;
        if o + len > end {
            return None;
        }
        out.push((cp, body[o..o + len].to_vec()));
        o += len;
    }
    Some(out)
}

fn make_fp(permute: bool) -> Fingerprint {
    // A small but realistic extension list (the wire order is up to
    // BoringSSL; we just need ≥2 extensions to make permutation visible).
    Fingerprint {
        extensions_order: vec![
            0x0000, // server_name
            0x002b, // supported_versions
            0x0033, // key_share
            0x000a, // supported_groups
            0x000d, // signature_algorithms
            0x0017, // extended_master_secret
            0x002d, // psk_key_exchange_modes
        ],
        alpn: vec!["h2".into()],
        supported_groups: vec![0x001D /* X25519 */],
        signature_algorithms: vec![0x0403, 0x0804, 0x0401],
        grease: false, // bracketing GREASE is orthogonal to permutation
        permute_extensions: permute,
        ..Default::default()
    }
}

#[test]
fn permute_disabled_is_deterministic_across_handshakes() {
    let a = capture_client_hello(make_fp(false));
    let b = capture_client_hello(make_fp(false));
    let c = capture_client_hello(make_fp(false));
    eprintln!("deterministic order: {:04x?}", a);
    assert_eq!(a, b, "non-permuted ClientHellos differ");
    assert_eq!(b, c, "non-permuted ClientHellos differ");
}

#[test]
fn permute_enabled_changes_order_across_handshakes() {
    // Permutation is random, so two handshakes *might* coincidentally
    // produce the same order. Run a handful and assert that not all of
    // them are identical (probability of false negative ≈ 1/N!^k ~ 0).
    let samples: Vec<Vec<u16>> = (0..6)
        .map(|_| capture_client_hello(make_fp(true)))
        .collect();
    let unique: std::collections::HashSet<_> = samples.iter().collect();
    eprintln!(
        "permuted samples ({} unique): {:04x?}",
        unique.len(),
        samples
    );
    assert!(
        unique.len() > 1,
        "SSL_set_permute_extensions did not produce any variation across 6 handshakes: {samples:04x?}",
    );
    // And: the *set* of codepoints emitted must be identical across runs,
    // modulo the `padding` extension (codepoint 0x15 = 21), which BoringSSL
    // emits only when the rest of the ClientHello falls short of the
    // 512-byte boundary. Since the random session_id / key_share bytes
    // change every handshake, padding may legitimately appear or vanish.
    fn strip_padding(s: &[u16]) -> std::collections::BTreeSet<u16> {
        s.iter().copied().filter(|&cp| cp != 0x0015).collect()
    }
    let set0 = strip_padding(&samples[0]);
    for s in &samples[1..] {
        let setn = strip_padding(s);
        assert_eq!(
            set0, setn,
            "permutation changed the extension *set*, not just order"
        );
    }
}

#[test]
fn trust_anchors_extension_is_emitted_on_the_wire() {
    let mut fp = make_fp(false);
    fp.extensions_order.push(TRUST_ANCHORS_EXTENSION);
    // Empty list is enough: BoringSSL still writes the codepoint.
    fp.trust_anchors = Some(Vec::new());
    let captured = capture_client_hello(fp);
    assert!(
        captured.contains(&TRUST_ANCHORS_EXTENSION),
        "ClientHello missing trust_anchors (0xCA34): {captured:04x?}",
    );
}

#[test]
fn grease_sigalgs_prepends_grease_to_signature_algorithms() {
    let mut off = make_fp(false);
    off.grease = true;
    off.grease_sigalgs = false;
    let first_off = first_sigalg(&capture_raw_client_hello(off)).expect("sigalgs");
    assert!(
        !is_grease(first_off),
        "sigalgs GREASE leaked out with grease_sigalgs=false: {first_off:04x}"
    );

    let mut on = make_fp(false);
    on.grease = true;
    on.grease_sigalgs = true;
    let first_on = first_sigalg(&capture_raw_client_hello(on)).expect("sigalgs");
    assert!(
        is_grease(first_on),
        "signature_algorithms did not start with GREASE: {first_on:04x}"
    );
}
