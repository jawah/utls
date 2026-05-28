//! `MemoryBio` - the Python-owned I/O bridge.
//!
//! Every TLS handshake/record operation in utls flows through a pair of
//! BoringSSL `BIO`s: one for ciphertext flowing *into* the SSL state machine
//! (peer -> us) and one for ciphertext flowing *out* (us -> peer). Python is
//! responsable for actually moving those bytes on whatever transport it likes
//! (blocking socket, asyncio.Transport, trio Stream, ...).
//!
//! ### Why we don't expose BoringSSL's `BIO_new_pair` directly
//!
//! `BIO_new_pair` (or `BIO_s_mem`) does what we need, but the stdlib `ssl`
//! module exposes `MemoryBIO` with very specific semantics - `pending`, `eof`,
//! `write_eof()` - that we need to mirror exactly. Wrapping a single
//! `BIO_s_mem` per direction and tracking `eof` ourselves is the simplest way
//! to preserve those semantics.
//!
//! ### Thread safety
//!
//! BoringSSL `BIO`s are not internally synchronized. A `MemoryBio` must not
//! be touched concurrently from multiple threads. The PyO3 layer wraps the
//! Rust object in a `Mutex` to enforce this from Python.

use std::ptr::NonNull;

use crate::error::{Error, Result};

/// One side of an in-memory BoringSSL `BIO`, plus an explicit `eof` flag.
///
/// Owns the underlying `*mut BIO` and frees it on drop.
pub struct MemoryBio {
    bio: NonNull<boring_sys::BIO>,
    eof: bool,
}

// SAFETY: the underlying BIO is not Sync, but as long as we never expose it
// to multiple threads simultaneously (the Python layer enforces this with a
// Mutex), `Send` is sound - ownership can transfer between threads.
unsafe impl Send for MemoryBio {}

impl std::fmt::Debug for MemoryBio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryBio")
            .field("pending", &self.pending())
            .field("eof", &self.eof)
            .finish()
    }
}

impl MemoryBio {
    /// Allocate a new in-memory BIO. Returns `Err(Protocol)` if BoringSSL OOMs.
    pub fn new() -> Result<Self> {
        crate::init();
        // SAFETY: `BIO_s_mem()` returns a static method table pointer that is
        // valid for the lifetime of the program. `BIO_new` either returns
        // NULL or a freshly allocated, owned BIO. We check for NULL.
        let raw = unsafe {
            let method = boring_sys::BIO_s_mem();
            boring_sys::BIO_new(method)
        };
        let bio = NonNull::new(raw).ok_or_else(|| Error::from_boring_queue("BIO_new"))?;

        // Mark the BIO as accepting writes after EOF so that `pending` keeps
        // working as expected even after `write_eof()`.
        // BIO_set_mem_eof_return(bio, -1) -> reads after EOF return WANT_READ
        // (instead of returning 0 which BoringSSL would treat as success).
        // SAFETY: `bio` is a valid memory BIO we just allocated.
        unsafe {
            boring_sys::BIO_set_mem_eof_return(bio.as_ptr(), -1);
        }

        Ok(MemoryBio { bio, eof: false })
    }

    /// Raw pointer escape hatch for the `Context` to wire this BIO to an
    /// `SSL` handle. The pointer remains owned by `self`.
    pub(crate) fn as_ptr(&self) -> *mut boring_sys::BIO {
        self.bio.as_ptr()
    }

    /// Number of bytes currently buffered in this BIO.
    pub fn pending(&self) -> usize {
        // SAFETY: `BIO_ctrl_pending` is read-only and always safe on a valid BIO.
        unsafe { boring_sys::BIO_ctrl_pending(self.bio.as_ptr()) }
    }

    /// Whether the caller has marked this BIO as having received EOF.
    /// Mirrors `ssl.MemoryBIO.eof`.
    pub fn eof(&self) -> bool {
        self.eof && self.pending() == 0
    }

    /// Append bytes that just arrived from the peer.
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if self.eof {
            return Err(Error::Usage(
                "cannot write to a MemoryBIO after write_eof() was called".into(),
            ));
        }
        if data.is_empty() {
            return Ok(0);
        }
        // BoringSSL caps a single BIO_write at INT_MAX bytes; we trust callers
        // not to hand us 2 GiB of TLS ciphertext at once.
        let len = data.len().min(i32::MAX as usize);
        // SAFETY: pointer + length describe a valid &[u8] slice; BIO_write
        // does not retain the pointer beyond the call.
        let written = unsafe {
            boring_sys::BIO_write(self.bio.as_ptr(), data.as_ptr() as *const _, len as i32)
        };
        if written < 0 {
            Err(Error::from_boring_queue("BIO_write (MemoryBIO)"))
        } else {
            Ok(written as usize)
        }
    }

    /// Drain up to `max` bytes that the SSL state machine has produced for
    /// the peer (or that the caller wrote into this BIO).
    ///
    /// `max == None` means "give me everything pending".
    pub fn read(&mut self, max: Option<usize>) -> Result<Vec<u8>> {
        let pending = self.pending();
        if pending == 0 {
            return Ok(Vec::new());
        }
        let want = max.map(|m| m.min(pending)).unwrap_or(pending);
        let mut buf = vec![0u8; want];
        // SAFETY: buf has `want` bytes of writable storage.
        let n = unsafe {
            boring_sys::BIO_read(self.bio.as_ptr(), buf.as_mut_ptr() as *mut _, want as i32)
        };
        if n < 0 {
            return Err(Error::from_boring_queue("BIO_read (MemoryBIO)"));
        }
        buf.truncate(n as usize);
        Ok(buf)
    }

    /// Mark the BIO as having received EOF from the peer. Subsequent
    /// handshake/read attempts will surface as [`Error::Eof`] once the
    /// buffered bytes are exhausted.
    pub fn write_eof(&mut self) {
        self.eof = true;
    }
}

impl Drop for MemoryBio {
    fn drop(&mut self) {
        // SAFETY: we own the BIO; BIO_free is the documented destructor.
        unsafe {
            boring_sys::BIO_free(self.bio.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_bytes() {
        let mut bio = MemoryBio::new().unwrap();
        assert_eq!(bio.pending(), 0);
        assert!(!bio.eof());
        let n = bio.write(b"hello").unwrap();
        assert_eq!(n, 5);
        assert_eq!(bio.pending(), 5);

        let out = bio.read(Some(3)).unwrap();
        assert_eq!(out, b"hel");
        assert_eq!(bio.pending(), 2);

        let rest = bio.read(None).unwrap();
        assert_eq!(rest, b"lo");
        assert_eq!(bio.pending(), 0);
    }

    #[test]
    fn write_after_eof_is_rejected() {
        let mut bio = MemoryBio::new().unwrap();
        bio.write_eof();
        let err = bio.write(b"x").unwrap_err();
        matches!(err, Error::Usage(_));
    }

    #[test]
    fn eof_only_reports_true_when_drained() {
        let mut bio = MemoryBio::new().unwrap();
        bio.write(b"abc").unwrap();
        bio.write_eof();
        assert!(!bio.eof()); // still bytes pending
        bio.read(None).unwrap();
        assert!(bio.eof());
    }
}
