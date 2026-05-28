//! Opaque session token, used for TLS session resumption.
//!
//! The Python facade exposes [`Session`] as an opaque, pickleable object. The
//! pickle format is **the DER serialization of a BoringSSL `SSL_SESSION`**, so
//! a session captured on one host can be replayed on another running the same
//! BoringSSL build. We deliberately do not promise cross-version stability;
//! a `Session` from an older utls may be silently rejected on resumption.

use std::ptr::NonNull;

use crate::error::{Error, Result};

/// Owned BoringSSL `SSL_SESSION`.
pub struct Session {
    raw: NonNull<boring_sys::SSL_SESSION>,
}

// SAFETY: `SSL_SESSION` is internally refcounted by BoringSSL and safe to
// hand between threads as long as only one thread mutates at a time. Our
// usage is read-mostly (`get1` on a connected SSL, `set1` on a fresh one),
// so `Send` is sufficient.
unsafe impl Send for Session {}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("ptr", &self.raw.as_ptr())
            .finish()
    }
}

impl Session {
    /// Construct from an owned `*mut SSL_SESSION`. Increments no refcount;
    /// caller must already hold a reference.
    ///
    /// # Safety
    ///
    /// `raw` must be a valid `SSL_SESSION*` that the caller is donating
    /// ownership of (i.e. came from `SSL_get1_session` or equivalent).
    pub(crate) unsafe fn from_owned_ptr(raw: *mut boring_sys::SSL_SESSION) -> Option<Self> {
        NonNull::new(raw).map(|raw| Session { raw })
    }

    /// Raw pointer accessor for the Context to call `SSL_set_session`.
    pub(crate) fn as_ptr(&self) -> *mut boring_sys::SSL_SESSION {
        self.raw.as_ptr()
    }

    /// Serialize the session to a DER blob suitable for storage / pickling.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        // i2d_SSL_SESSION uses the OpenSSL "double-call" convention:
        //   first call with NULL output pointer to get required length,
        //   then call with a real buffer.
        // SAFETY: SSL_SESSION pointer is valid; passing NULL out-buf is the
        // documented length-query form.
        let len = unsafe { boring_sys::i2d_SSL_SESSION(self.raw.as_ptr(), std::ptr::null_mut()) };
        if len <= 0 {
            return Err(Error::from_boring_queue("i2d_SSL_SESSION (length)"));
        }
        let mut buf = vec![0u8; len as usize];
        let mut p = buf.as_mut_ptr();
        // SAFETY: `p` points to `len` writable bytes; BoringSSL advances `p`.
        let written = unsafe { boring_sys::i2d_SSL_SESSION(self.raw.as_ptr(), &mut p) };
        if written <= 0 {
            return Err(Error::from_boring_queue("i2d_SSL_SESSION (write)"));
        }
        buf.truncate(written as usize);
        Ok(buf)
    }

    /// Parse a session from a DER blob produced by [`Self::to_der`].
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::Usage("session DER blob is empty".into()));
        }
        let mut p = bytes.as_ptr();
        // SAFETY: pointer + length describe a valid buffer; d2i advances `p`.
        let raw = unsafe {
            boring_sys::d2i_SSL_SESSION(
                std::ptr::null_mut(),
                &mut p,
                bytes.len() as std::ffi::c_long,
            )
        };
        let raw = NonNull::new(raw).ok_or_else(|| Error::from_boring_queue("d2i_SSL_SESSION"))?;
        Ok(Session { raw })
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        // SAFETY: SSL_SESSION_up_ref is the documented refcount bump.
        unsafe {
            boring_sys::SSL_SESSION_up_ref(self.raw.as_ptr());
        }
        Session { raw: self.raw }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: pairs with up_ref / the original up_ref donated by
        // SSL_get1_session.
        unsafe {
            boring_sys::SSL_SESSION_free(self.raw.as_ptr());
        }
    }
}
