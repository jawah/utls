//! Default trust-store loading.
//!
//! Delegates to BoringSSL's `SSL_CTX_set_default_verify_paths`, which:
//!
//! * On Linux/BSD: reads the bundle/dir baked into BoringSSL at compile time
//!   (typically `/etc/ssl/certs/` or `/etc/pki/tls/certs/`).
//! * Honors `SSL_CERT_FILE` (single PEM bundle) and `SSL_CERT_DIR`
//!   (hash-named directory) environment variables, matching the stdlib `ssl`
//!   module's behavior on Unix.

use crate::context::{Context, Purpose};
use crate::error::{Error, Result};

pub fn load_default(ctx: &Context, _purpose: Purpose) -> Result<()> {
    // SAFETY: ctx is valid.
    let rc = unsafe { boring_sys::SSL_CTX_set_default_verify_paths(ctx.as_ptr()) };
    if rc != 1 {
        return Err(Error::from_boring_queue("SSL_CTX_set_default_verify_paths"));
    }
    Ok(())
}
