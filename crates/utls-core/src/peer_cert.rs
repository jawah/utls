//! Peer-certificate introspection - the data backing
//! `SSLObject.getpeercert(binary_form=False)`.
//!
//! Stdlib `_ssl` exposes a dict shape that downstream code (urllib3, requests'
//! deprecated `ssl.match_hostname`, monitoring tools) parses. Reproducing that
//! shape faithfully means walking BoringSSL's X.509 object directly. We do
//! that here, returning a plain Rust struct that the PyO3 layer turns into a
//! `PyDict` with the exact keys and ordering CPython produces.
//!
//! The fields we surface are the ones CPython's `_decode_certificate`
//! populates and that real code reads:
//!
//! * `subject` / `issuer` - tuple-of-RDNs-of-(name, value) pairs.
//! * `version` - 1-indexed integer (BoringSSL gives 0-indexed).
//! * `serialNumber` - uppercase hex string, no separators.
//! * `notBefore` / `notAfter` - `"May 25 12:00:00 2026 GMT"` style.
//! * `subjectAltName` - tuple of `(kind, value)` like `("DNS", "x.example")`
//!   or `("IP Address", "1.2.3.4")`.
//!
//! Deliberately omitted (rarely consumed, would balloon FFI surface): OCSP
//! responder URLs, CA Issuers, CRL distribution points. Callers that need
//! those can grab the DER via `binary_form=True` and parse with `cryptography`.

use std::os::raw::{c_char, c_int};
use std::ptr;

use crate::error::Result;

/// Parsed view of the leaf peer certificate, in a shape the Python facade can
/// turn directly into the stdlib `getpeercert()` dict.
#[derive(Debug, Default, Clone)]
pub struct PeerCertInfo {
    /// 1-indexed X.509 version (1, 2, or 3).
    pub version: i64,
    /// Uppercase hex serial number, no separators (matches CPython).
    pub serial_number: String,
    /// `"May 25 12:00:00 2026 GMT"` - exactly what `ASN1_TIME_print` writes.
    pub not_before: String,
    pub not_after: String,
    /// Sequence of RDNs. Each inner `Vec` holds `(attr_name, attr_value)`
    /// pairs. We always emit one pair per RDN - multi-valued RDNs are
    /// extremely rare and CPython collapses them in the same way for the
    /// majority of real-world certs (single-attribute RDNs).
    pub subject: Vec<Vec<(String, String)>>,
    pub issuer: Vec<Vec<(String, String)>>,
    /// `[(kind, value), ...]` where `kind` is one of `"DNS"`, `"IP Address"`,
    /// `"email"`, `"URI"`, `"Registered ID"`, `"DirName"`, `"othername"`,
    /// `"X400Name"`, `"EdiPartyName"`. Matches CPython's labels exactly.
    pub subject_alt_name: Vec<(String, String)>,
}

/// Extract `PeerCertInfo` from the SSL's peer-leaf certificate.
///
/// Returns `Ok(None)` if no peer certificate is available - handshake hasn't
/// completed, the peer didn't send a cert, or `verify_mode=CERT_NONE` with a
/// pre-shared cipher. Otherwise returns the populated struct.
///
/// # Safety
///
/// `ssl` must be a non-null, live `*mut SSL` that originated from BoringSSL.
pub unsafe fn peer_cert_info(ssl: *mut boring_sys::SSL) -> Result<Option<PeerCertInfo>> {
    // SAFETY: caller upholds the SSL pointer contract; `SSL_get_peer_certificate`
    // returns either NULL or a refcounted X509* that we must free.
    let cert = unsafe { boring_sys::SSL_get_peer_certificate(ssl) };
    if cert.is_null() {
        return Ok(None);
    }
    // Make sure we always free the refcount bump from SSL_get_peer_certificate
    // even on early-return error paths.
    struct CertGuard(*mut boring_sys::X509);
    impl Drop for CertGuard {
        fn drop(&mut self) {
            // SAFETY: we obtained `self.0` from SSL_get_peer_certificate
            // (refcount bumped), so X509_free here brings the refcount back
            // to where it was on entry.
            unsafe { boring_sys::X509_free(self.0) };
        }
    }
    let _guard = CertGuard(cert);

    // SAFETY: `cert` is non-null and outlives this call thanks to CertGuard.
    Ok(Some(unsafe { cert_info_from_x509(cert) }?))
}

/// Decode a raw DER-encoded X.509 certificate into the same `PeerCertInfo`
/// shape `peer_cert_info` produces. Backs
/// `SSLContext.get_ca_certs(binary_form=False)` and the
/// `Certificate.get_info()` shim consumed by urllib3.future's chain walker.
pub fn decode_cert_der(der: &[u8]) -> Result<Option<PeerCertInfo>> {
    if der.is_empty() {
        return Ok(None);
    }
    let mut p = der.as_ptr();
    // SAFETY: `der` describes a valid byte slice; `d2i_X509` either parses
    // and returns an owned X509* or returns NULL on malformed input.
    let cert = unsafe {
        boring_sys::d2i_X509(std::ptr::null_mut(), &mut p, der.len() as std::ffi::c_long)
    };
    if cert.is_null() {
        return Ok(None);
    }
    struct CertGuard(*mut boring_sys::X509);
    impl Drop for CertGuard {
        fn drop(&mut self) {
            // SAFETY: `self.0` came from d2i_X509 (refcount=1) so we own it.
            unsafe { boring_sys::X509_free(self.0) };
        }
    }
    let _guard = CertGuard(cert);

    // SAFETY: `cert` is non-null and outlives this call thanks to CertGuard.
    Ok(Some(unsafe { cert_info_from_x509(cert) }?))
}

/// Common cert-decoding core. Used by both `peer_cert_info` (live SSL peer
/// cert) and `decode_cert_der` (standalone DER).
///
/// # Safety
///
/// `cert` must be a non-null, valid `*mut X509` whose lifetime exceeds this
/// call (it is borrowed, not freed).
unsafe fn cert_info_from_x509(cert: *mut boring_sys::X509) -> Result<PeerCertInfo> {
    // X509_get_version returns the on-the-wire integer (0 = v1, 1 = v2,
    // 2 = v3). Stdlib reports the human-readable 1-indexed form.
    let mut info = PeerCertInfo {
        version: unsafe { boring_sys::X509_get_version(cert) as i64 } + 1,
        ..Default::default()
    };

    // SAFETY: cert is valid; X509_get_serialNumber returns a pointer owned by
    // the X509 (no free needed). i2a_ASN1_INTEGER writes uppercase hex.
    let sn_ptr = unsafe { boring_sys::X509_get_serialNumber(cert) };
    info.serial_number = if sn_ptr.is_null() {
        String::new()
    } else {
        bio_capture(|bio| unsafe { boring_sys::i2a_ASN1_INTEGER(bio, sn_ptr) })?
    };

    // SAFETY: cert is valid; X509_get0_notBefore/notAfter return pointers
    // owned by the X509.
    let nb = unsafe { boring_sys::X509_get0_notBefore(cert) };
    let na = unsafe { boring_sys::X509_get0_notAfter(cert) };
    info.not_before = if nb.is_null() {
        String::new()
    } else {
        bio_capture(|bio| unsafe { boring_sys::ASN1_TIME_print(bio, nb) })?
    };
    info.not_after = if na.is_null() {
        String::new()
    } else {
        bio_capture(|bio| unsafe { boring_sys::ASN1_TIME_print(bio, na) })?
    };

    // SAFETY: cert is valid; these return pointers owned by the X509.
    let subj = unsafe { boring_sys::X509_get_subject_name(cert) };
    let issu = unsafe { boring_sys::X509_get_issuer_name(cert) };
    if !subj.is_null() {
        info.subject = unsafe { walk_name(subj) }?;
    }
    if !issu.is_null() {
        info.issuer = unsafe { walk_name(issu) }?;
    }

    // X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL) returns an
    // owned GENERAL_NAMES* (== STACK_OF(GENERAL_NAME)*) that we must free
    // with GENERAL_NAMES_free.
    let san = unsafe {
        boring_sys::X509_get_ext_d2i(
            cert,
            boring_sys::NID_subject_alt_name,
            ptr::null_mut(),
            ptr::null_mut(),
        ) as *mut boring_sys::GENERAL_NAMES
    };
    if !san.is_null() {
        let result = unsafe { walk_san(san) };
        // SAFETY: san is owned by us (d2i_*) and not null.
        unsafe { boring_sys::GENERAL_NAMES_free(san) };
        info.subject_alt_name = result?;
    }

    Ok(info)
}

/// Walk an `X509_NAME`, returning a tuple-of-RDNs-of-(short_or_long_name, value).
/// Mirrors CPython's `_create_tuple_for_X509_NAME`.
///
/// # Safety
///
/// `name` must be a non-null, valid `*mut X509_NAME` whose lifetime exceeds
/// this call (it is borrowed, not freed).
unsafe fn walk_name(name: *mut boring_sys::X509_NAME) -> Result<Vec<Vec<(String, String)>>> {
    // SAFETY: name validity per caller contract.
    let count = unsafe { boring_sys::X509_NAME_entry_count(name) };
    if count <= 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        // SAFETY: 0 <= i < count.
        let entry = unsafe { boring_sys::X509_NAME_get_entry(name, i) };
        if entry.is_null() {
            continue;
        }
        // SAFETY: entry is valid.
        let obj = unsafe { boring_sys::X509_NAME_ENTRY_get_object(entry) };
        let data = unsafe { boring_sys::X509_NAME_ENTRY_get_data(entry) };
        if obj.is_null() || data.is_null() {
            continue;
        }
        let attr = obj_name(obj);
        let value = asn1_string_to_utf8(data)?;
        out.push(vec![(attr, value)]);
    }
    Ok(out)
}

/// Walk a `GENERAL_NAMES` stack, returning `[(kind, value), ...]`.
///
/// # Safety
///
/// `gens` must be a non-null, valid `*mut GENERAL_NAMES` whose lifetime
/// exceeds this call.
unsafe fn walk_san(gens: *mut boring_sys::GENERAL_NAMES) -> Result<Vec<(String, String)>> {
    // BoringSSL's stack helpers take `*const OPENSSL_STACK` (== `_STACK`).
    // Same trick as `peer_chain_der`: cast the typed-stack pointer.
    let opaque = gens as *const boring_sys::OPENSSL_STACK;
    // SAFETY: opaque points to the same allocation as `gens`.
    let n = unsafe { boring_sys::sk_num(opaque) };
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        // SAFETY: 0 <= i < n.
        let gn = unsafe { boring_sys::sk_value(opaque, i) as *const boring_sys::GENERAL_NAME };
        if gn.is_null() {
            continue;
        }
        // GENERAL_NAME's struct is opaque in bindgen output, so we can't
        // reach into `gn->type` / `gn->d`. Instead we use `GENERAL_NAME_print`
        // which writes BoringSSL's canonical text form - `DNS:foo`,
        // `IP Address:1.2.3.4`, `email:x@y`, `URI:https://...`, etc. - that
        // matches the labels CPython emits one-for-one. We split on the first
        // colon; the value may legitimately contain further colons (IPv6,
        // URIs), so we use `splitn(2)`.
        let printed = bio_capture(|bio| unsafe { boring_sys::GENERAL_NAME_print(bio, gn) })?;
        if let Some((kind, value)) = printed.split_once(':') {
            out.push((kind.to_string(), value.to_string()));
        }
    }
    Ok(out)
}

/// Resolve an `ASN1_OBJECT` to its preferred display name. Uses the long
/// name when BoringSSL knows the OID, falling back to the dotted numeric
/// form - matching what CPython does via `OBJ_obj2txt(_, _, _, 0)`.
fn obj_name(obj: *mut boring_sys::ASN1_OBJECT) -> String {
    let mut buf = [0u8; 80];
    // SAFETY: `obj` is valid per caller; `buf` is 80 bytes writable.
    let n = unsafe {
        boring_sys::OBJ_obj2txt(
            buf.as_mut_ptr() as *mut c_char,
            buf.len() as c_int,
            obj,
            0, // 0 = use long/short name when known
        )
    };
    if n <= 0 {
        return String::new();
    }
    // OBJ_obj2txt may report a length larger than `buf.len()`; clamp.
    let n = (n as usize).min(buf.len());
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// Decode an `ASN1_STRING` (in any standard string subtype) to UTF-8.
///
/// # Safety
///
/// `s` must be a non-null, valid `*mut ASN1_STRING` whose lifetime exceeds
/// this call.
fn asn1_string_to_utf8(s: *mut boring_sys::ASN1_STRING) -> Result<String> {
    let mut out: *mut u8 = ptr::null_mut();
    // SAFETY: `s` is valid; `&mut out` is a writable `*mut *mut u8`.
    let n = unsafe { boring_sys::ASN1_STRING_to_UTF8(&mut out, s) };
    if n < 0 || out.is_null() {
        return Ok(String::new());
    }
    // SAFETY: ASN1_STRING_to_UTF8 wrote `n` bytes at `out`; we copy them
    // out, then free with OPENSSL_free as required by the API.
    let slice = unsafe { std::slice::from_raw_parts(out, n as usize) };
    let s = String::from_utf8_lossy(slice).into_owned();
    // SAFETY: `out` was allocated by BoringSSL's allocator.
    unsafe { boring_sys::OPENSSL_free(out as *mut std::ffi::c_void) };
    Ok(s)
}

/// Run a BoringSSL printer function that writes into a BIO, returning the
/// produced text. Strips a trailing newline (a few printers - notably
/// `ASN1_TIME_print` does NOT - but `GENERAL_NAME_print` doesn't either;
/// `i2a_ASN1_INTEGER` is consistent. We still trim defensively.).
fn bio_capture<F>(write: F) -> Result<String>
where
    F: FnOnce(*mut boring_sys::BIO) -> c_int,
{
    // SAFETY: BIO_s_mem returns a static method; BIO_new wraps it.
    let bio = unsafe { boring_sys::BIO_new(boring_sys::BIO_s_mem()) };
    if bio.is_null() {
        return Ok(String::new());
    }
    struct BioGuard(*mut boring_sys::BIO);
    impl Drop for BioGuard {
        fn drop(&mut self) {
            // SAFETY: self.0 is the BIO we just allocated.
            unsafe { boring_sys::BIO_free(self.0) };
        }
    }
    let _g = BioGuard(bio);

    let rc = write(bio);
    if rc < 0 {
        return Ok(String::new());
    }

    let mut data: *mut c_char = ptr::null_mut();
    // SAFETY: bio is valid; BIO_get_mem_data writes the internal buffer
    // pointer (borrowed, not owned by us) and returns its length.
    let len = unsafe { boring_sys::BIO_get_mem_data(bio, &mut data) };
    if len <= 0 || data.is_null() {
        return Ok(String::new());
    }
    // SAFETY: BoringSSL guarantees `len` bytes are readable at `data`.
    let slice = unsafe { std::slice::from_raw_parts(data as *const u8, len as usize) };
    let mut s = String::from_utf8_lossy(slice).into_owned();
    while s.ends_with('\n') || s.ends_with('\r') {
        s.pop();
    }
    Ok(s)
}
