//! Server-side ClientHello capture for `SSLObject.get_fingerprint()`.
//!
//! When a [`Context`](crate::Context) is constructed in server mode we install
//! a `SSL_CTX_set_select_certificate_cb` trampoline that fires very early in
//! the handshake, *before* certificate selection. The trampoline copies the
//! raw `ClientHello` bytes into a per-connection slot keyed by an SSL ex-data
//! index. After the handshake (or even after a failed handshake), the Python
//! facade calls [`captured_client_hello`] to retrieve those bytes and parses
//! them through the existing `fingerprint::capture::parse_client_hello`
//! pipeline.
//!
//! ## Safety / threading
//!
//! The callback runs synchronously inside `SSL_do_handshake`, which itself
//! runs in the Python thread that called `do_handshake()` (the GIL is
//! released by the PyO3 layer for the duration of that call). The callback
//! therefore touches **only** Rust state - never Python - and uses a
//! `Mutex<Option<Vec<u8>>>` for the captured bytes.
//!
//! ## Why `select_certificate_cb`
//!
//! BoringSSL exposes the raw `ClientHello` (with all extensions intact) via
//! `SSL_CLIENT_HELLO`'s split-out fields. We rebuild a full TLS handshake
//! record wrapper around those fields so the existing
//! `parse_client_hello` parser - which expects a record-wrapped CH - can
//! be reused unchanged.

use std::os::raw::c_int;
use std::sync::{Mutex, OnceLock};

/// Per-`SSL*` capture slot held in `Box<CaptureSlot>` and attached via
/// `SSL_set_ex_data`. The Mutex is overkill in practice (the callback and
/// the reader never race on a single connection) but it keeps the type
/// `Sync` without unsafe juggling.
#[derive(Debug)]
pub struct CaptureSlot {
    pub bytes: Mutex<Option<Vec<u8>>>,
}

impl CaptureSlot {
    pub fn new() -> Self {
        Self {
            bytes: Mutex::new(None),
        }
    }
}

impl Default for CaptureSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot, lazily-allocated `SSL_get_ex_new_index` slot. BoringSSL hands
/// out a fresh integer the first time we ask; subsequent calls reuse it.
fn ex_data_index() -> c_int {
    static IDX: OnceLock<c_int> = OnceLock::new();
    *IDX.get_or_init(|| {
        // SAFETY: pure FFI; passing NULL for the optional argp/new_func/...
        // hooks is documented as "no extra bookkeeping". We manage the
        // Box ourselves in `attach_capture_slot`/`drop_capture_slot`.
        unsafe {
            boring_sys::SSL_get_ex_new_index(
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                None,
                None,
            )
        }
    })
}

/// Attach a fresh [`CaptureSlot`] to `ssl`. Must be paired with
/// [`drop_capture_slot`] when the connection is dropped.
///
/// # Safety
/// `ssl` must be a live `SSL*` not yet started.
pub unsafe fn attach_capture_slot(ssl: *mut boring_sys::SSL) {
    let slot = Box::new(CaptureSlot::new());
    let ptr = Box::into_raw(slot) as *mut std::ffi::c_void;
    // SAFETY: ex_data API takes opaque pointers; we own and free in `drop`.
    unsafe {
        boring_sys::SSL_set_ex_data(ssl, ex_data_index(), ptr);
    }
}

/// Free the [`CaptureSlot`] previously attached by [`attach_capture_slot`].
///
/// # Safety
/// `ssl` must be the same handle the slot was attached to.
pub unsafe fn drop_capture_slot(ssl: *mut boring_sys::SSL) {
    // SAFETY: see attach.
    let ptr = unsafe { boring_sys::SSL_get_ex_data(ssl, ex_data_index()) };
    if !ptr.is_null() {
        // SAFETY: we boxed this pointer in `attach_capture_slot`.
        let _ = unsafe { Box::from_raw(ptr as *mut CaptureSlot) };
        // SAFETY: clear the slot to avoid double-free if anyone else
        // walks ex_data.
        unsafe {
            boring_sys::SSL_set_ex_data(ssl, ex_data_index(), std::ptr::null_mut());
        }
    }
}

/// Return a clone of the captured ClientHello bytes, if any.
///
/// # Safety
/// `ssl` must be a live handle previously fed to [`attach_capture_slot`].
pub unsafe fn captured_client_hello(ssl: *mut boring_sys::SSL) -> Option<Vec<u8>> {
    // SAFETY: see attach.
    let ptr = unsafe { boring_sys::SSL_get_ex_data(ssl, ex_data_index()) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: we own this Box; reborrow as &CaptureSlot for the read.
    let slot = unsafe { &*(ptr as *const CaptureSlot) };
    slot.bytes.lock().unwrap().clone()
}

/// The C-ABI trampoline installed on the server's `SSL_CTX`.
///
/// Called by BoringSSL exactly once per inbound connection, after the
/// `ClientHello` is parsed but before certificate selection. We:
///   1. Read the split-out fields from `SSL_CLIENT_HELLO`.
///   2. Reconstruct a full TLS handshake record around them.
///   3. Stash the record bytes on the connection's capture slot.
///   4. Return `ssl_select_cert_success` to let BoringSSL continue.
///
/// Any allocation/parse error is silently dropped - capture is best-effort
/// and must never break the handshake.
///
/// # Safety
/// FFI entry point. `client_hello` must be a valid `SSL_CLIENT_HELLO*` for
/// the duration of the call (BoringSSL guarantees this).
pub unsafe extern "C" fn select_certificate_cb(
    client_hello: *const boring_sys::SSL_CLIENT_HELLO,
) -> boring_sys::ssl_select_cert_result_t {
    // Always allow the handshake to proceed.
    let ok = boring_sys::ssl_select_cert_result_t::ssl_select_cert_success;
    if client_hello.is_null() {
        return ok;
    }
    // SAFETY: BoringSSL guarantees the struct is live for this call.
    let ch = unsafe { &*client_hello };
    if ch.ssl.is_null() || ch.client_hello.is_null() || ch.client_hello_len == 0 {
        return ok;
    }

    // Reconstruct the original handshake record:
    //   record header   : 0x16 || legacy_version(2) || record_length(2)
    //   handshake header: 0x01 || handshake_length(3)
    //   handshake body  : <client_hello bytes from SSL_CLIENT_HELLO>
    //
    // `client_hello`/`client_hello_len` from BoringSSL is the handshake
    // body starting at `legacy_version` (no record/handshake headers).
    // SAFETY: pointer + len describe a valid &[u8] for the call duration.
    let body = unsafe { std::slice::from_raw_parts(ch.client_hello, ch.client_hello_len) };

    let hs_len = body.len();
    if hs_len > 0x00FF_FFFF {
        return ok; // pathological; drop capture rather than panic
    }
    // record body length = handshake header (4) + handshake body
    let rec_len = hs_len + 4;
    if rec_len > 0xFFFF {
        return ok; // larger than a single TLS record can carry; drop capture
    }

    let mut buf = Vec::with_capacity(5 + rec_len);
    buf.push(0x16); // ContentType: handshake
    buf.push(0x03); // legacy_version: TLS 1.0 wire-version (matches Chrome)
    buf.push(0x01);
    buf.extend_from_slice(&(rec_len as u16).to_be_bytes());
    buf.push(0x01); // HandshakeType: ClientHello
    let hs_len_be = (hs_len as u32).to_be_bytes();
    buf.extend_from_slice(&hs_len_be[1..]); // 3-byte length
    buf.extend_from_slice(body);

    // SAFETY: ex_data lookup; ptr was set by `attach_capture_slot`.
    let ptr = unsafe { boring_sys::SSL_get_ex_data(ch.ssl, ex_data_index()) };
    if !ptr.is_null() {
        // SAFETY: same provenance as attach.
        let slot = unsafe { &*(ptr as *const CaptureSlot) };
        *slot.bytes.lock().unwrap() = Some(buf);
    }
    ok
}
