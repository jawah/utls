//! Error types for utls-core.
//!
//! These map onto Python exceptions in the PyO3 layer:
//!
//! | Variant                  | Python exception                  |
//! |--------------------------|-----------------------------------|
//! | [`Error::WantRead`]      | `SSLWantReadError`                |
//! | [`Error::WantWrite`]     | `SSLWantWriteError`               |
//! | [`Error::Eof`]           | `SSLEOFError`                     |
//! | [`Error::ZeroReturn`]    | `SSLZeroReturnError`              |
//! | [`Error::Verification`]  | `SSLCertVerificationError`        |
//! | [`Error::Protocol { .. }`] | `SSLError`                      |
//! | [`Error::Usage(_)`]      | `ValueError`                      |
//! | [`Error::Io(_)`]         | `OSError` (wrapped in `SSLError`) |
//! | [`Error::Unsupported(_)`]| `NotImplementedError`             |

use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors raised by utls-core.
///
/// The variants are deliberately narrow: anything that maps to a single Python
/// exception subclass gets its own variant, and everything else falls into
/// [`Error::Protocol`] which carries the BoringSSL error queue contents.
#[derive(Debug, Error)]
pub enum Error {
    /// Handshake/read needs more bytes from the peer.
    #[error("operation would block: need to read more from the peer")]
    WantRead,

    /// Handshake/write needs the caller to flush outgoing data.
    #[error("operation would block: need to send buffered data to the peer")]
    WantWrite,

    /// Unexpected EOF (TCP closed mid-record).
    #[error("unexpected EOF on TLS connection")]
    Eof,

    /// Clean TLS-level shutdown received (close_notify).
    #[error("peer sent close_notify; no more data will be received")]
    ZeroReturn,

    /// Certificate chain verification failed.
    #[error("certificate verification failed: {reason}")]
    Verification {
        /// Human-readable reason.
        reason: String,
        /// BoringSSL verify result code (`X509_V_ERR_*`), if available.
        verify_code: Option<i64>,
    },

    /// A protocol-level error reported by BoringSSL.
    #[error("TLS protocol error: {message}")]
    Protocol {
        /// Human-readable message assembled from BoringSSL's error queue.
        message: String,
        /// The first error code from BoringSSL's queue, for callers that want it.
        code: Option<u32>,
    },

    /// The caller used the API incorrectly (e.g. wrong protocol constant,
    /// invalid fingerprint dict). Maps to Python `ValueError`.
    #[error("usage error: {0}")]
    Usage(String),

    /// I/O error from a Rust-side source (currently only the trust-store
    /// loaders touch the filesystem on Unix).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A feature was requested that this build does not support.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl Error {
    /// Drain BoringSSL's per-thread error queue into a single [`Error::Protocol`].
    ///
    /// Always returns an `Err` so callsites can write `return Err(Error::from_boring_queue("op"))`.
    pub fn from_boring_queue(context_hint: &str) -> Self {
        // SAFETY: ERR_get_error is safe to call from any thread; it operates
        // on a thread-local queue and returns 0 when empty.
        let mut first: Option<u32> = None;
        let mut messages: Vec<String> = Vec::new();
        loop {
            let code = unsafe { boring_sys::ERR_get_error() };
            if code == 0 {
                break;
            }
            // Convert error code to string. `ERR_error_string_n` is the
            // bounds-checked variant; 256 bytes is enough per BoringSSL docs.
            let mut buf = [0u8; 256];
            // SAFETY: buffer is valid and big enough; function nul-terminates.
            unsafe {
                boring_sys::ERR_error_string_n(
                    code,
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                );
            }
            let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let msg = String::from_utf8_lossy(&buf[..nul]).into_owned();
            first.get_or_insert(code as u32);
            messages.push(msg);
        }
        let message = if messages.is_empty() {
            format!("{context_hint}: no error info available from BoringSSL")
        } else {
            format!("{context_hint}: {}", messages.join("; "))
        };
        Error::Protocol {
            message,
            code: first,
        }
    }
}
