//! Smoke tests for the public surface of `utls-core`.
//!
//! Real handshake-against-the-internet tests live in the Python integration
//! suite; here we only check that the API shape behaves.

use utls_core::context::Protocol;
use utls_core::{Context, MemoryBio, TlsVersion, VerifyMode};

#[test]
fn context_constructs_with_safe_defaults() {
    let ctx = Context::new(Protocol::TlsClient).expect("ctx");
    assert_eq!(ctx.verify_mode(), VerifyMode::Required);
    assert!(ctx.check_hostname());
}

#[test]
fn version_bounds_round_trip() {
    let ctx = Context::new(Protocol::TlsClient).unwrap();
    ctx.set_version_bounds(TlsVersion::Tls1_3, TlsVersion::Tls1_3)
        .unwrap();
    assert!(ctx
        .set_version_bounds(TlsVersion::Tls1_3, TlsVersion::Tls1_2)
        .is_err());
}

#[test]
fn wrap_bio_requires_hostname_when_verifying() {
    let ctx = Context::new(Protocol::TlsClient).unwrap();
    let i = MemoryBio::new().unwrap();
    let o = MemoryBio::new().unwrap();
    let err = ctx.wrap_bio(&i, &o, None, None).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("server_hostname"), "got: {msg}");
}

#[test]
fn check_hostname_invariant_matches_stdlib() {
    // Stdlib semantics (per prior-session correction):
    //   - set_check_hostname(false) is *allowed* while CERT_REQUIRED.
    //   - The only forbidden combination is CERT_NONE + check_hostname=true.
    let ctx = Context::new(Protocol::TlsClient).unwrap();
    ctx.set_check_hostname(false).unwrap();
    ctx.set_check_hostname(true).unwrap();
    ctx.set_verify_mode(VerifyMode::None).unwrap();
    assert!(ctx.set_check_hostname(true).is_err());
    ctx.set_check_hostname(false).unwrap();
}
