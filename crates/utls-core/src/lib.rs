//! utls-core
//!
//! Pure-Rust core for the `utls` Python library. Wraps `boring-sys` (raw
//! BoringSSL FFI) with a small, opinionated, *client-only* surface:
//!
//! * [`context::Context`]  - analogue of `ssl.SSLContext`.
//! * [`bio::MemoryBio`]    - Python-owned I/O bridge.
//! * [`session::Session`]  - opaque resumption token.
//! * [`fingerprint::Fingerprint`] - the differentiator: full ClientHello control.
//! * [`trust_store`]       - platform-specific default trust loading.
//!
//! ## Design invariants
//!
//! 1. **No global state.** A one-shot library init is performed on first
//!    [`Context::new`] (BoringSSL is already mostly init-free, but we still
//!    centralize it here so we never have to think about it again).
//! 2. **MemoryBIO-first.** Nothing in this crate ever calls into a socket;
//!    Python owns I/O. Sockets are wired up one layer above (in the Python
//!    facade) on top of [`bio::MemoryBio`].
//! 3. **No background threads.** Anything that needs polling or async behavior
//!    is the caller's problem.
//! 4. **No callbacks into Python from non-Python threads.** The PyO3 layer
//!    enforces this; this crate must not make that promise hard to keep.
//! 5. **Client + server.** Server-side TLS is supported with the same
//!    BoringSSL backend; fingerprint application is client-only (irrelevant
//!    server-side), but ClientHello *capture* is wired up for servers via
//!    [`server_fp`] so `SSLObject.get_fingerprint()` reports peer behaviour.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

pub mod bio;
pub mod context;
pub mod error;
pub mod fingerprint;
pub mod peer_cert;
pub mod server_fp;
pub mod session;
pub mod trust_store;
pub mod verify;

pub use bio::MemoryBio;
pub use context::{
    Context, HandshakeState, Purpose, SniAction, SniDispatcher, SniSslHandle, TlsVersion,
    VerifyMode,
};
pub use error::{Error, Result};
pub use fingerprint::{Fingerprint, FingerprintBuilder};
pub use session::Session;

use std::sync::Once;

/// One-shot library initialization. Idempotent and thread-safe.
///
/// BoringSSL's modern API is largely init-free, but we centralize any future
/// requirement here so callers never have to think about ordering.
pub fn init() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: BoringSSL's CRYPTO_library_init is documented to be safe to
        // call from any thread and is idempotent. We additionally gate it
        // behind a `Once` so it runs exactly one time per process.
        unsafe {
            boring_sys::CRYPTO_library_init();
        }
    });
}

/// Version string of the BoringSSL build vendored into this crate.
///
/// BoringSSL itself refuses to be versioned; its `OPENSSL_VERSION_TEXT`
/// macro is permanently frozen at ``"OpenSSL 1.1.1 (compatible; BoringSSL)"``,
/// so the only drift handle that actually exists is the `boring-sys`
/// crate version, which pins a specific upstream snapshot at build time.
/// We append it to the stock text so downstream callers get both the
/// ecosystem-sniffable ``"BoringSSL"`` substring and a real version they
/// can correlate with bug reports.
///
/// Example:
///
/// ```text
/// OpenSSL 1.1.1 (compatible; BoringSSL; boring-sys 5.1.0)
/// ```
pub fn boringssl_version() -> &'static str {
    static FULL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    FULL.get_or_init(|| {
        // SAFETY: `OPENSSL_VERSION_TEXT` is a NUL-terminated C string literal
        // exported by boring-sys; its bytes are valid UTF-8 ASCII.
        let bytes = boring_sys::OPENSSL_VERSION_TEXT;
        let len = bytes.len().saturating_sub(1); // strip trailing NUL
                                                 // SAFETY: bytes[..len] is valid UTF-8 (ASCII).
        let stock = unsafe { std::str::from_utf8_unchecked(&bytes[..len]) };
        let bs_ver = env!("BORING_SYS_VERSION");
        // Splice the boring-sys version into the parenthesised suffix so the
        // result still parses as the familiar ``OpenSSL <ver> (...)`` shape.
        if let Some(prefix) = stock.strip_suffix(')') {
            format!("{prefix}; boring-sys {bs_ver})")
        } else {
            format!("{stock} (boring-sys {bs_ver})")
        }
    })
}
