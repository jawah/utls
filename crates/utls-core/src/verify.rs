//! Certificate-chain and hostname verification helpers.
//!
//! Most of the heavy lifting is done by BoringSSL's built-in X509 verifier
//! once we've called `SSL_CTX_set_verify` and (for hostname) `SSL_set1_host`.
//! This module exists mainly to:
//!
//! 1. Translate BoringSSL verify codes (`X509_V_ERR_*`) into a human-readable
//!    reason for the [`Error::Verification`] variant.
//! 2. Provide a one-call helper for extracting the peer certificate chain in
//!    DER form, used by `SSLObject.getpeercert(binary_form=True)`.
//!
//! Hostname verification policy: we **always** enable strict hostname
//! matching when `check_hostname=True`, including:
//!
//! * IDN A-label comparison (BoringSSL does this for us - we feed it the
//!   already-encoded ASCII form from the Python facade).
//! * No wildcard matching beyond the leftmost label
//!   (`X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS`).
//! * No matching of IP literals against the CN field
//!   (`X509_CHECK_FLAG_NEVER_CHECK_SUBJECT`).
//!
//! These flags are applied in [`crate::context::Context::enable_hostname_check`].

use crate::error::{Error, Result};

/// Translate a BoringSSL `X509_V_ERR_*` code into a stable, human-readable
/// reason string. The codes are documented in
/// `boringssl/include/openssl/x509_vfy.h`.
pub fn verify_code_reason(code: i64) -> &'static str {
    // Only the common ones; everything else falls through to a generic label.
    // The numeric values are deliberately hard-coded rather than imported
    // because the `boring-sys` bindings expose them as `c_int` constants
    // whose names sometimes drift between minor versions.
    match code {
        0 => "ok",
        2 => "unable to get issuer certificate",
        3 => "unable to get certificate CRL",
        7 => "certificate signature failure",
        9 => "certificate is not yet valid",
        10 => "certificate has expired",
        18 => "self-signed certificate",
        19 => "self-signed certificate in certificate chain",
        20 => "unable to get local issuer certificate",
        21 => "unable to verify the first certificate",
        22 => "certificate chain too long",
        23 => "certificate revoked",
        24 => "invalid CA certificate",
        25 => "path length constraint exceeded",
        26 => "unsupported certificate purpose",
        27 => "certificate not trusted",
        28 => "certificate rejected",
        62 => "hostname mismatch",
        _ => "certificate verification failed",
    }
}

/// Build an [`Error::Verification`] from the verify result currently stored
/// on an `SSL*`.
///
/// # Safety
///
/// `ssl` must be a non-null, live `*mut SSL`.
pub unsafe fn verification_error(ssl: *mut boring_sys::SSL) -> Error {
    // SAFETY: caller guarantees `ssl` validity.
    let code = unsafe { boring_sys::SSL_get_verify_result(ssl) } as i64;
    let reason = verify_code_reason(code).to_string();
    Error::Verification {
        reason,
        verify_code: Some(code),
    }
}

/// Extract the peer certificate chain in DER form.
///
/// Returns an empty Vec if no peer certificate is available (e.g. the
/// handshake hasn't completed yet or the cipher suite doesn't authenticate
/// the peer).
///
/// # Safety
///
/// `ssl` must be a non-null, live `*mut SSL`.
pub unsafe fn peer_chain_der(ssl: *mut boring_sys::SSL) -> Result<Vec<Vec<u8>>> {
    // SAFETY: caller guarantees `ssl` validity.
    let stack = unsafe { boring_sys::SSL_get_peer_cert_chain(ssl) };
    if stack.is_null() {
        return Ok(Vec::new());
    }
    // boring-sys 4 only surfaces the generic `sk_num` / `sk_value` taking
    // a `*const _STACK`. We cast `stack_st_X509*` to it; the layouts are
    // identical (BoringSSL's stack types are all wrappers over `_STACK`).
    let opaque = stack as *const boring_sys::_STACK;
    // SAFETY: opaque points to the same allocation as `stack`.
    let n = unsafe { boring_sys::sk_num(opaque) };
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        // SAFETY: i < n.
        let cert_ptr = unsafe { boring_sys::sk_value(opaque, i) } as *mut boring_sys::X509;
        if cert_ptr.is_null() {
            continue;
        }
        // SAFETY: cert is a valid X509*.
        let len = unsafe { boring_sys::i2d_X509(cert_ptr, std::ptr::null_mut()) };
        if len <= 0 {
            return Err(Error::from_boring_queue("i2d_X509 (length)"));
        }
        let mut buf = vec![0u8; len as usize];
        let mut p = buf.as_mut_ptr();
        // SAFETY: buf has `len` writable bytes.
        let written = unsafe { boring_sys::i2d_X509(cert_ptr, &mut p) };
        if written <= 0 {
            return Err(Error::from_boring_queue("i2d_X509 (write)"));
        }
        buf.truncate(written as usize);
        out.push(buf);
    }
    Ok(out)
}
