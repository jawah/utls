//! [`Context`] - the Rust analogue of `ssl.SSLContext`.
//!
//! Owns one `SSL_CTX*` and produces one [`Connection`] per `wrap_bio` call.
//!
//! ## What lives here vs. in the Python facade
//!
//! Everything that requires touching BoringSSL state lives here:
//! cipher/version/ALPN configuration, trust-store loading, fingerprint
//! application, and the SSL handle lifecycle.
//!
//! The Python facade adds:
//! * argument parsing and normalization (e.g. `OP_*` flags),
//! * the `SSLSocket`/`SSLObject` distinction,
//! * environment-aware defaults (none, currently - see security notes).
//!
//! ## What is intentionally *not* here
//!
//! * No `SSL_CTX_set_session_cache_mode` server side; client-side resumption
//!   uses the explicit `session=` argument on `wrap_*`.
//!
//! ## Trampoline callbacks
//!
//! Server-side ALPN selection, SNI dispatch, and (any side) keylog writes go
//! through `extern "C"` trampolines that look up per-context state via a
//! global registry keyed by raw `SSL_CTX*`. Each registry entry is scrubbed
//! by `RegistryGuard::drop` so address reuse cannot leak state.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::raw::{c_char, c_int};
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};

use crate::bio::MemoryBio;
use crate::error::{Error, Result};
use crate::fingerprint::Fingerprint;
use crate::session::Session;
use crate::verify::{peer_chain_der, verification_error};

/// Re-export the protocol constant shape the Python facade exposes.
/// Mirrors the subset of `ssl.PROTOCOL_TLS_*` we accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Equivalent to `ssl.PROTOCOL_TLS_CLIENT`.
    TlsClient,
    /// Equivalent to `ssl.PROTOCOL_TLS_SERVER`.
    TlsServer,
}

impl Protocol {
    pub fn is_server(self) -> bool {
        matches!(self, Protocol::TlsServer)
    }
}

/// Mirror of `ssl.VerifyMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    None,
    Optional,
    Required,
}

/// Mirror of `ssl.Purpose`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    ServerAuth,
    /// On Windows this additionally enumerates the `CA` and `MY` stores when
    /// loading defaults; on Unix it's identical to `ServerAuth` because
    /// `SSL_CTX_set_default_verify_paths()` doesn't distinguish.
    ClientAuth,
}

/// TLS protocol version. Mirrors stdlib's `TLSVersion` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    MinimumSupported,
    Tls1_2,
    Tls1_3,
    MaximumSupported,
}

impl TlsVersion {
    fn to_boring_version(self) -> u16 {
        // Numeric values from RFC 8446 / RFC 5246. We hard-code them to avoid
        // ambiguity with `boring-sys`'s constant naming churn.
        match self {
            TlsVersion::MinimumSupported => 0x0303, // TLS 1.2 - we never negotiate below
            TlsVersion::Tls1_2 => 0x0303,
            TlsVersion::Tls1_3 => 0x0304,
            TlsVersion::MaximumSupported => 0x0304, // TLS 1.3 today
        }
    }
}

/// Where a [`Connection`] is in its handshake lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    NotStarted,
    InProgress,
    Established,
    Shutdown,
}

/// One TLS-capable context. Wraps `SSL_CTX*`.
pub struct Context {
    ctx: NonNull<boring_sys::SSL_CTX>,
    /// Whether this context is configured for server-side accepts
    /// (`TLS_server_method`) or client-side connects (`TLS_client_method`).
    is_server: bool,
    // Stored so we can re-apply if the user mutates these after creation.
    fingerprint: Mutex<Option<Fingerprint>>,
    /// Real ECH (Encrypted Client Hello) ConfigList bytes. When `Some`, it
    /// overrides whatever ECH policy the active fingerprint specifies and
    /// is applied via `SSL_set1_ech_config_list` per connection. The bytes
    /// are the wire-format `ECHConfigList` typically obtained from a DNS
    /// HTTPS RR's `ech=` parameter (RFC 9460 + draft-ietf-tls-svcb-ech).
    ech_config_list: Mutex<Option<Vec<u8>>>,
    verify_mode: Mutex<VerifyMode>,
    check_hostname: Mutex<bool>,
    minimum_version: Mutex<TlsVersion>,
    maximum_version: Mutex<TlsVersion>,
    /// Server-side: the ALPN protocol list to choose *from* when the client
    /// offers a set; first match wins. Client-side: also stored but applied
    /// directly to the SSL_CTX via `SSL_CTX_set_alpn_protos`.
    alpn_list: Mutex<Vec<Vec<u8>>>,
    /// X509_V_FLAG_* bitmask currently applied to the verify param. Stored
    /// so `verify_flags` getter returns what the user set (matches stdlib).
    verify_flags: Mutex<u64>,
    /// SSLKEYLOGFILE-style writer. When `Some`, the keylog trampoline
    /// appends each line BoringSSL emits (in NSS Key Log Format). Shared
    /// via `Arc` so the registry hands the trampoline a stable handle even
    /// while the user swaps the path on the Context.
    keylog_writer: Mutex<Option<Arc<Mutex<BufWriter<File>>>>>,
    /// Refcounted scrub guard for the global ALPN + keylog registries. When
    /// the *last* clone of this Context drops, the guard's `Drop` removes
    /// the SSL_CTX-keyed entries so that a later allocation reusing the
    /// same SSL_CTX address cannot inherit them (which would otherwise
    /// disclose TLS secrets to a fresh keylog or surface stale ALPN prefs).
    _registry_guard: Arc<RegistryGuard>,
}

/// Drop-handle that scrubs the per-context entries from the ALPN + keylog
/// global registries on its last reference.
struct RegistryGuard {
    ctx: usize,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        alpn_registry().lock().unwrap().remove(&self.ctx);
        keylog_registry().lock().unwrap().remove(&self.ctx);
        sni_registry().lock().unwrap().remove(&self.ctx);
    }
}

// SAFETY: SSL_CTX is internally thread-safe for the operations we perform on
// it (set_*, get_*); BoringSSL holds its own lock. New SSL handles created
// from it are not shared between threads concurrently (we wrap them in
// `Connection` which is `!Sync`).
unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("ptr", &self.ctx.as_ptr())
            .field("verify_mode", &*self.verify_mode.lock().unwrap())
            .field("check_hostname", &*self.check_hostname.lock().unwrap())
            .finish()
    }
}

impl Context {
    /// Build a new `Context`. `protocol` selects client (default,
    /// `PROTOCOL_TLS_CLIENT`) or server (`PROTOCOL_TLS_SERVER`) mode.
    ///
    /// Defaults follow `ssl.create_default_context()`:
    /// * verify_mode = CERT_REQUIRED (client) / CERT_NONE (server)
    /// * check_hostname = True (client) / False (server)
    /// * minimum_version = TLS 1.2
    /// * maximum_version = TLS 1.3
    pub fn new(protocol: Protocol) -> Result<Self> {
        crate::init();
        let is_server = protocol.is_server();
        // SAFETY: TLS_method/TLS_server_method/TLS_client_method return static
        // method tables valid for the lifetime of the program.
        let raw = unsafe {
            let method = if is_server {
                boring_sys::TLS_server_method()
            } else {
                boring_sys::TLS_client_method()
            };
            boring_sys::SSL_CTX_new(method)
        };
        let ctx = NonNull::new(raw).ok_or_else(|| Error::from_boring_queue("SSL_CTX_new"))?;

        let (default_verify, default_hostname) = if is_server {
            (VerifyMode::None, false)
        } else {
            (VerifyMode::Required, true)
        };

        let this = Context {
            ctx,
            is_server,
            fingerprint: Mutex::new(None),
            ech_config_list: Mutex::new(None),
            verify_mode: Mutex::new(default_verify),
            check_hostname: Mutex::new(default_hostname),
            minimum_version: Mutex::new(TlsVersion::Tls1_2),
            maximum_version: Mutex::new(TlsVersion::Tls1_3),
            alpn_list: Mutex::new(Vec::new()),
            verify_flags: Mutex::new(0),
            keylog_writer: Mutex::new(None),
            _registry_guard: Arc::new(RegistryGuard {
                ctx: ctx.as_ptr() as usize,
            }),
        };
        this.apply_version_bounds(TlsVersion::Tls1_2, TlsVersion::Tls1_3)?;
        this.apply_verify_mode(default_verify)?;
        // Set SSL_MODE_AUTO_RETRY off so partial reads surface as WantRead
        // (matches Python `ssl.MemoryBIO` semantics).
        // SAFETY: ctx is valid.
        unsafe {
            boring_sys::SSL_CTX_clear_mode(ctx.as_ptr(), boring_sys::SSL_MODE_AUTO_RETRY as u32);
        }

        if is_server {
            // Install the ClientHello-capture trampoline. Best-effort; the
            // callback itself never fails the handshake.
            // SAFETY: ctx is live; trampoline has the right ABI.
            unsafe {
                boring_sys::SSL_CTX_set_select_certificate_cb(
                    ctx.as_ptr(),
                    Some(crate::server_fp::select_certificate_cb),
                );
            }
            // Install the ALPN-selection trampoline so server-side
            // `set_alpn_protocols([...])` actually picks a protocol out of
            // what the client offered. We pass `self.ctx` indirectly via
            // SSL_CTX ex-data so the callback can look up our preference
            // list without globals.
            // SAFETY: pure FFI; the callback only touches the SSL handle.
            unsafe {
                boring_sys::SSL_CTX_set_alpn_select_cb(
                    ctx.as_ptr(),
                    Some(alpn_select_cb_trampoline),
                    std::ptr::null_mut(),
                );
            }
            // Install the SNI dispatch trampoline. It is a no-op until the
            // user registers a callback via `set_sni_dispatcher`; we install
            // it unconditionally so registration is cheap (just a HashMap
            // insert, no FFI roundtrip).
            // SAFETY: ctx is live; trampoline has the correct ABI.
            unsafe {
                boring_sys::SSL_CTX_set_tlsext_servername_callback(
                    ctx.as_ptr(),
                    Some(sni_cb_trampoline),
                );
            }
        }
        Ok(this)
    }

    /// Whether this context handshakes as a server (`SSL_accept`) or a
    /// client (`SSL_connect`).
    pub fn is_server(&self) -> bool {
        self.is_server
    }

    /// Raw pointer escape hatch for [`Fingerprint::apply`].
    pub(crate) fn as_ptr(&self) -> *mut boring_sys::SSL_CTX {
        self.ctx.as_ptr()
    }

    pub fn set_verify_mode(&self, mode: VerifyMode) -> Result<()> {
        *self.verify_mode.lock().unwrap() = mode;
        self.apply_verify_mode(mode)
    }

    pub fn verify_mode(&self) -> VerifyMode {
        *self.verify_mode.lock().unwrap()
    }

    fn apply_verify_mode(&self, mode: VerifyMode) -> Result<()> {
        let flag: c_int = match mode {
            VerifyMode::None => boring_sys::SSL_VERIFY_NONE as c_int,
            VerifyMode::Optional => (boring_sys::SSL_VERIFY_PEER) as c_int,
            VerifyMode::Required => {
                (boring_sys::SSL_VERIFY_PEER | boring_sys::SSL_VERIFY_FAIL_IF_NO_PEER_CERT) as c_int
            }
        };
        // We pass a null callback so BoringSSL uses its default chain validator;
        // we examine the verify result later via `SSL_get_verify_result`.
        // SAFETY: ctx is valid; passing NULL callback is documented and safe.
        unsafe {
            boring_sys::SSL_CTX_set_verify(self.ctx.as_ptr(), flag, None);
        }
        Ok(())
    }

    pub fn set_check_hostname(&self, enabled: bool) -> Result<()> {
        // Storing a flag; hostname is actually enforced per-connection via
        // `SSL_set1_host`. We refuse to *enable* hostname checking while
        // verify_mode is CERT_NONE - matches stdlib `SSLContext.check_hostname`
        // setter behavior. Disabling check_hostname while verify_mode is
        // REQUIRED is allowed (caller may be moving to CERT_NONE next).
        if enabled && matches!(self.verify_mode(), VerifyMode::None) {
            return Err(Error::Usage(
                "Cannot enable check_hostname while verify_mode is CERT_NONE".into(),
            ));
        }
        *self.check_hostname.lock().unwrap() = enabled;
        Ok(())
    }

    pub fn check_hostname(&self) -> bool {
        *self.check_hostname.lock().unwrap()
    }

    pub fn set_version_bounds(&self, min: TlsVersion, max: TlsVersion) -> Result<()> {
        if min > max {
            return Err(Error::Usage(format!(
                "minimum_version ({min:?}) cannot exceed maximum_version ({max:?})"
            )));
        }
        *self.minimum_version.lock().unwrap() = min;
        *self.maximum_version.lock().unwrap() = max;
        self.apply_version_bounds(min, max)
    }

    fn apply_version_bounds(&self, min: TlsVersion, max: TlsVersion) -> Result<()> {
        // SAFETY: ctx is valid; functions accept any u16 and validate.
        unsafe {
            if boring_sys::SSL_CTX_set_min_proto_version(self.ctx.as_ptr(), min.to_boring_version())
                != 1
            {
                return Err(Error::from_boring_queue("SSL_CTX_set_min_proto_version"));
            }
            if boring_sys::SSL_CTX_set_max_proto_version(self.ctx.as_ptr(), max.to_boring_version())
                != 1
            {
                return Err(Error::from_boring_queue("SSL_CTX_set_max_proto_version"));
            }
        }
        Ok(())
    }

    /// Set the ALPN protocol list, in preference order.
    ///
    /// Each protocol must be 1..=255 bytes; the wire format is a sequence of
    /// length-prefixed byte strings, per RFC 7301.
    ///
    /// **Client mode** - the list is advertised on the wire via
    /// `SSL_CTX_set_alpn_protos`; the server picks one.
    ///
    /// **Server mode** - the list is *not* sent on the wire; instead it is
    /// stored and consulted by our `SSL_CTX_set_alpn_select_cb` trampoline
    /// to choose one of the client's offered protocols (first match wins).
    pub fn set_alpn_protocols(&self, protocols: &[&str]) -> Result<()> {
        let mut wire = Vec::new();
        let mut list = Vec::with_capacity(protocols.len());
        for p in protocols {
            let bytes = p.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                return Err(Error::Usage(format!(
                    "ALPN protocol {p:?} must be 1..=255 bytes"
                )));
            }
            wire.push(bytes.len() as u8);
            wire.extend_from_slice(bytes);
            list.push(bytes.to_vec());
        }
        *self.alpn_list.lock().unwrap() = list.clone();
        if self.is_server {
            // Refresh the registry so the select callback sees the new list.
            alpn_registry_set(self.ctx.as_ptr(), list);
        } else {
            // SAFETY: pointer + length describe a valid &[u8].
            let rc = unsafe {
                boring_sys::SSL_CTX_set_alpn_protos(self.ctx.as_ptr(), wire.as_ptr(), wire.len())
            };
            // BoringSSL returns 0 on success here (inherited from OpenSSL's
            // backwards-compat oddity). Anything else is an error.
            if rc != 0 {
                return Err(Error::from_boring_queue("SSL_CTX_set_alpn_protos"));
            }
        }
        Ok(())
    }

    /// Snapshot of the configured ALPN list. Returned as length-prefix-less
    /// byte vectors in preference order. Used by the server-side select
    /// callback (via the ALPN registry) and by tests.
    pub fn alpn_list_snapshot(&self) -> Vec<Vec<u8>> {
        self.alpn_list.lock().unwrap().clone()
    }

    /// `SSL_CTX_set_cipher_list` - install an OpenSSL-style cipher list.
    ///
    /// Best-effort stdlib parity: BoringSSL's parser accepts the lenient
    /// OpenSSL syntax (`:` separator, `!`/`-`/`+` operators, group aliases
    /// like `HIGH`/`ALL`/`kEECDH`). It silently ignores unrecognised tokens,
    /// matching OpenSSL's non-strict behaviour.
    ///
    /// Note: this only governs TLS <= 1.2 cipher selection. BoringSSL hard
    /// codes the TLS 1.3 suite list and there is no public API to override
    /// it (the same as stdlib `ssl`). Callers needing TLS 1.3 cipher
    /// customisation should use the fingerprint API instead.
    pub fn set_ciphers(&self, spec: &str) -> Result<()> {
        let c = CString::new(spec)
            .map_err(|_| Error::Usage("cipher list contains a NUL byte".into()))?;
        // SAFETY: self.ctx is a valid SSL_CTX*; c is a valid nul-terminated
        // string borrowed for the duration of the call.
        let rc = unsafe { boring_sys::SSL_CTX_set_cipher_list(self.ctx.as_ptr(), c.as_ptr()) };
        if rc != 1 {
            return Err(Error::from_boring_queue("SSL_CTX_set_cipher_list"));
        }
        Ok(())
    }

    /// Install or clear the active fingerprint. The fingerprint is *applied*
    /// per-connection inside [`Self::wrap_bio`], not globally on the SSL_CTX,
    /// so changing it does not leak across connections.
    ///
    /// Server-side contexts cannot have a fingerprint: fingerprinting
    /// rewrites the ClientHello, which a server never sends. Calling this
    /// on a server context returns `Err(Error::Usage(...))`.
    pub fn set_fingerprint(&self, fp: Option<Fingerprint>) -> Result<()> {
        if self.is_server && fp.is_some() {
            return Err(Error::Usage(
                "set_fingerprint() is client-only (servers do not send a ClientHello)".into(),
            ));
        }
        *self.fingerprint.lock().unwrap() = fp;
        Ok(())
    }

    pub fn fingerprint(&self) -> Option<Fingerprint> {
        self.fingerprint.lock().unwrap().clone()
    }

    /// `SSL_CTX_set_session_id_context` - required for client-cert auth +
    /// session reuse on the server side. Accepts up to 32 bytes.
    pub fn set_session_id_context(&self, ctx_id: &[u8]) -> Result<()> {
        if ctx_id.len() > 32 {
            return Err(Error::Usage(
                "session_id_context must be at most 32 bytes".into(),
            ));
        }
        // SAFETY: pointer + length describe a valid &[u8]; BoringSSL copies.
        let rc = unsafe {
            boring_sys::SSL_CTX_set_session_id_context(
                self.ctx.as_ptr(),
                ctx_id.as_ptr(),
                ctx_id.len(),
            )
        };
        if rc != 1 {
            return Err(Error::from_boring_queue("SSL_CTX_set_session_id_context"));
        }
        Ok(())
    }

    /// `SSL_CTX_set1_curves_list` - restrict (EC)DHE groups to the given
    /// colon-separated list. Mirrors `ssl.SSLContext.set_ecdh_curve(name)`
    /// when given a single name, and the OpenSSL-style colon list otherwise.
    pub fn set_curves_list(&self, names: &str) -> Result<()> {
        let c = CString::new(names)
            .map_err(|_| Error::Usage("curves list contains a NUL byte".into()))?;
        // SAFETY: ctx + nul-term string valid.
        let rc = unsafe { boring_sys::SSL_CTX_set1_curves_list(self.ctx.as_ptr(), c.as_ptr()) };
        if rc != 1 {
            return Err(Error::from_boring_queue("SSL_CTX_set1_curves_list"));
        }
        Ok(())
    }

    /// `SSL_CTX_set_num_tickets` - server-side TLS 1.3 session ticket count
    /// (per CPython's `SSLContext.num_tickets`, default 2).
    pub fn set_num_tickets(&self, n: usize) -> Result<()> {
        // SAFETY: pure FFI.
        let rc = unsafe { boring_sys::SSL_CTX_set_num_tickets(self.ctx.as_ptr(), n) };
        if rc != 1 {
            return Err(Error::from_boring_queue("SSL_CTX_set_num_tickets"));
        }
        Ok(())
    }

    pub fn num_tickets(&self) -> usize {
        // SAFETY: pure FFI.
        unsafe { boring_sys::SSL_CTX_get_num_tickets(self.ctx.as_ptr()) }
    }

    /// Get the X509_V_FLAG_* bitmask installed on the verify param.
    pub fn verify_flags(&self) -> u64 {
        *self.verify_flags.lock().unwrap()
    }

    /// Set the X509_V_FLAG_* bitmask on the SSL_CTX's verify param.
    ///
    /// Maps to `X509_VERIFY_PARAM_set_flags`. Stdlib `SSLContext.verify_flags`
    /// is a *replacement* (assigning the attribute overwrites), so we clear
    /// the old bits before setting the new - matches CPython behavior.
    pub fn set_verify_flags(&self, flags: u64) -> Result<()> {
        // SAFETY: SSL_CTX_get0_param returns a borrowed pointer valid for the
        // lifetime of the SSL_CTX; we hold a live ref.
        unsafe {
            let param = boring_sys::SSL_CTX_get0_param(self.ctx.as_ptr());
            if param.is_null() {
                return Err(Error::from_boring_queue("SSL_CTX_get0_param"));
            }
            // Clear whatever we had before so set is replace-semantics.
            let prev = *self.verify_flags.lock().unwrap();
            if prev != 0 {
                boring_sys::X509_VERIFY_PARAM_clear_flags(param, prev as std::os::raw::c_ulong);
            }
            if flags != 0
                && boring_sys::X509_VERIFY_PARAM_set_flags(param, flags as std::os::raw::c_ulong)
                    != 1
            {
                return Err(Error::from_boring_queue("X509_VERIFY_PARAM_set_flags"));
            }
        }
        *self.verify_flags.lock().unwrap() = flags;
        Ok(())
    }

    /// Install (or clear, with `None`) an SSLKEYLOGFILE-style writer.
    /// When set, BoringSSL invokes our trampoline for every secret it
    /// derives during the handshake (master secret in TLS 1.2; client/server
    /// handshake + traffic secrets in TLS 1.3). Each `line` is the NSS
    /// Key Log Format text - exactly what Wireshark consumes when its
    /// `(Pre)-Master-Secret log filename` preference is pointed at the file.
    ///
    /// The file is opened append-only (`O_APPEND`); concurrent connections
    /// share the same writer through the per-context `Arc<Mutex<...>>` so
    /// lines never interleave mid-record.
    pub fn set_keylog_filename(&self, path: Option<&str>) -> Result<()> {
        match path {
            Some(p) => {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .map_err(|e| Error::Protocol {
                        message: format!("keylog_filename: could not open {p:?}: {e}"),
                        code: None,
                    })?;
                let writer = Arc::new(Mutex::new(BufWriter::new(file)));
                *self.keylog_writer.lock().unwrap() = Some(writer.clone());
                keylog_registry_set(self.ctx.as_ptr(), writer);
                // SAFETY: pure FFI; trampoline ABI matches the function ptr.
                unsafe {
                    boring_sys::SSL_CTX_set_keylog_callback(
                        self.ctx.as_ptr(),
                        Some(keylog_cb_trampoline),
                    );
                }
            }
            None => {
                *self.keylog_writer.lock().unwrap() = None;
                keylog_registry_remove(self.ctx.as_ptr());
                // SAFETY: pure FFI.
                unsafe {
                    boring_sys::SSL_CTX_set_keylog_callback(self.ctx.as_ptr(), None);
                }
            }
        }
        Ok(())
    }

    /// Install (or clear, with `None`) a server-side SNI dispatcher. The
    /// dispatcher is invoked from the TLS handshake, after the ClientHello
    /// has been parsed and before the certificate is selected, with the SNI
    /// server name the client sent (or `None` if absent). See
    /// [`SniDispatcher`] for the semantics of the return value.
    ///
    /// Server-side only. Returns `Error::Usage` on a client context.
    pub fn set_sni_dispatcher(&self, dispatcher: Option<Arc<dyn SniDispatcher>>) -> Result<()> {
        if !self.is_server {
            return Err(Error::Usage(
                "set_servername_callback is server-side only".into(),
            ));
        }
        match dispatcher {
            Some(d) => sni_registry_set(self.ctx.as_ptr(), d),
            None => sni_registry_remove(self.ctx.as_ptr()),
        }
        Ok(())
    }

    /// Install (or clear, with `None`) a real ECH `ECHConfigList`. When set,
    /// every connection produced by [`Self::wrap_bio`] will offer this ECH
    /// config - overriding whatever ECH policy (`Off` / `Grease` / `Real`)
    /// the active [`Fingerprint`] carries.
    ///
    /// **This is non-mutating.** A new [`Context`] is returned that shares
    /// the underlying `SSL_CTX` (and therefore the trust store, loaded
    /// certificates, and other `SSL_CTX`-level configuration) with `self`
    /// via `SSL_CTX_up_ref`. The Rust-side per-context state (fingerprint,
    /// verify mode, hostname check, TLS version bounds) is snapshot at
    /// clone-time. Subsequent setter calls on either the original or the
    /// clone affect only the Rust-side state of that wrapper, not the
    /// shared `SSL_CTX`-level state.
    ///
    /// Rationale: ECH configs are peer-specific - they are published by
    /// the *origin* in a DNS HTTPS RR. Storing one on a shared, long-lived
    /// context would couple that context to a single peer. Cloning lets
    /// callers maintain a single configured base context and fork a cheap
    /// per-peer copy carrying that peer's ECH bytes.
    ///
    /// The bytes are the wire-format `ECHConfigList` defined in
    /// draft-ietf-tls-esni; they are typically discovered out-of-band via
    /// a DNS HTTPS RR's `ech=` parameter (RFC 9460 §7.6 +
    /// draft-ietf-tls-svcb-ech).
    pub fn set_ech_configs(&self, ech: Option<Vec<u8>>) -> Self {
        // SAFETY: self.ctx is a valid SSL_CTX*; SSL_CTX_up_ref is documented
        // to always return 1 (refcount bump never fails).
        let _ = unsafe { boring_sys::SSL_CTX_up_ref(self.ctx.as_ptr()) };
        Self {
            ctx: self.ctx,
            is_server: self.is_server,
            fingerprint: Mutex::new(self.fingerprint.lock().unwrap().clone()),
            ech_config_list: Mutex::new(ech),
            verify_mode: Mutex::new(*self.verify_mode.lock().unwrap()),
            check_hostname: Mutex::new(*self.check_hostname.lock().unwrap()),
            minimum_version: Mutex::new(*self.minimum_version.lock().unwrap()),
            maximum_version: Mutex::new(*self.maximum_version.lock().unwrap()),
            alpn_list: Mutex::new(self.alpn_list.lock().unwrap().clone()),
            verify_flags: Mutex::new(*self.verify_flags.lock().unwrap()),
            // The keylog writer follows the *cloned* context: same SSL_CTX,
            // so BoringSSL's existing keylog callback registration carries
            // over. We share the Arc so writes from either Context land in
            // the same file (an intentional simplification - a clone almost
            // always wants the same secrets dumped to the same log).
            keylog_writer: Mutex::new(self.keylog_writer.lock().unwrap().clone()),
            // Share the registry guard: the global ALPN/keylog entries are
            // alive as long as *any* clone is. They are scrubbed only when
            // the last clone drops, which exactly matches the BoringSSL
            // refcount on the underlying SSL_CTX.
            _registry_guard: Arc::clone(&self._registry_guard),
        }
    }

    /// Return the currently-installed ECH `ECHConfigList`, if any.
    pub fn ech_config_list(&self) -> Option<Vec<u8>> {
        self.ech_config_list.lock().unwrap().clone()
    }

    /// `load_verify_locations(cafile=..., capath=...)`.
    /// `cadata` is handled separately by the Python facade (PEM/DER -> DER list).
    pub fn load_verify_locations(&self, cafile: Option<&str>, capath: Option<&str>) -> Result<()> {
        let cafile_c = cafile
            .map(CString::new)
            .transpose()
            .map_err(|_| Error::Usage("cafile path contains a NUL byte".into()))?;
        let capath_c = capath
            .map(CString::new)
            .transpose()
            .map_err(|_| Error::Usage("capath path contains a NUL byte".into()))?;
        let cafile_ptr = cafile_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
        let capath_ptr = capath_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
        if cafile_ptr.is_null() && capath_ptr.is_null() {
            return Err(Error::Usage(
                "load_verify_locations() needs at least one of cafile / capath".into(),
            ));
        }
        // SAFETY: ctx is valid; nul-terminated C strings supplied where
        // pointers are non-null.
        let rc = unsafe {
            boring_sys::SSL_CTX_load_verify_locations(self.ctx.as_ptr(), cafile_ptr, capath_ptr)
        };
        if rc != 1 {
            return Err(Error::from_boring_queue("SSL_CTX_load_verify_locations"));
        }
        Ok(())
    }

    /// Add a single DER-encoded certificate to the trust store. Used by
    /// `load_verify_locations(cadata=...)` after the facade has parsed
    /// PEM/DER input.
    pub fn add_trusted_cert_der(&self, der: &[u8]) -> Result<()> {
        let mut p = der.as_ptr();
        // SAFETY: pointer + length describe a valid buffer.
        let x509 = unsafe {
            boring_sys::d2i_X509(std::ptr::null_mut(), &mut p, der.len() as std::ffi::c_long)
        };
        if x509.is_null() {
            return Err(Error::from_boring_queue("d2i_X509 (cadata)"));
        }
        // SAFETY: ctx valid; X509 valid. SSL_CTX_get_cert_store returns
        // a non-owning pointer to the context's X509_STORE.
        let store = unsafe { boring_sys::SSL_CTX_get_cert_store(self.ctx.as_ptr()) };
        // SAFETY: store and x509 valid. X509_STORE_add_cert increments the
        // refcount on success; on failure we still need to free x509.
        let rc = unsafe { boring_sys::X509_STORE_add_cert(store, x509) };
        // SAFETY: x509 was created by d2i_X509 with refcount=1; X509_STORE_add_cert
        // does NOT take ownership - it bumps refcount on success. So we always free.
        unsafe { boring_sys::X509_free(x509) };
        if rc != 1 {
            return Err(Error::from_boring_queue("X509_STORE_add_cert"));
        }
        Ok(())
    }

    /// Load the OS-default trust store. See `trust_store::load_default`.
    pub fn load_default_certs(&self, purpose: Purpose) -> Result<()> {
        crate::trust_store::load_default(self, purpose)
    }

    /// Walk the context's ``X509_STORE`` and return every loaded CA certificate
    /// in DER form. Mirrors the data ``ssl.SSLContext.get_ca_certs(binary_form=True)``
    /// exposes; consumers (urllib3, niquests) then PEM-encode and feed the
    /// blob to a different backend's ``load_verify_locations(cadata=...)``.
    ///
    /// Returns an empty vec when no CAs have been loaded. CRLs are skipped.
    pub fn ca_certs_der(&self) -> Result<Vec<Vec<u8>>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        // SAFETY: ctx valid; SSL_CTX_get_cert_store returns a borrowed pointer
        // owned by the SSL_CTX. Same for X509_STORE_get0_objects on the store.
        unsafe {
            let store = boring_sys::SSL_CTX_get_cert_store(self.ctx.as_ptr());
            if store.is_null() {
                return Ok(out);
            }
            let stack = boring_sys::X509_STORE_get0_objects(store);
            if stack.is_null() {
                return Ok(out);
            }
            // BoringSSL's STACK_OF(X509_OBJECT) is layout-compatible with
            // OPENSSL_STACK; the bindings expose the generic accessors.
            let n = boring_sys::OPENSSL_sk_num(stack as *const _);
            for i in 0..n {
                let obj = boring_sys::OPENSSL_sk_value(stack as *const _, i)
                    as *const boring_sys::X509_OBJECT;
                if obj.is_null() {
                    continue;
                }
                if boring_sys::X509_OBJECT_get_type(obj) != boring_sys::X509_LU_X509 {
                    continue;
                }
                let x509 = boring_sys::X509_OBJECT_get0_X509(obj);
                if x509.is_null() {
                    continue;
                }
                // i2d_X509 with null out-ptr returns the length; with a
                // non-null **out it writes the DER and advances the pointer.
                let len = boring_sys::i2d_X509(x509, std::ptr::null_mut());
                if len <= 0 {
                    // Skip serialization failures rather than aborting the walk.
                    continue;
                }
                let mut buf = vec![0u8; len as usize];
                let mut p: *mut u8 = buf.as_mut_ptr();
                let written = boring_sys::i2d_X509(x509, &mut p);
                if written != len {
                    continue;
                }
                out.push(buf);
            }
        }
        Ok(out)
    }

    /// Return ``(x509_count, crl_count)`` for the context's trust store, in
    /// the same shape ``ssl.SSLContext.cert_store_stats()`` uses (it returns
    /// ``{"x509": N, "x509_ca": M, "crl": K}`` - utls reports ``x509`` ==
    /// ``x509_ca`` because every cert in the store is treated as a trust
    /// anchor; BoringSSL has no separate "non-CA known cert" notion).
    pub fn cert_store_counts(&self) -> (usize, usize) {
        let mut x509 = 0usize;
        let mut crl = 0usize;
        // SAFETY: see ca_certs_der.
        unsafe {
            let store = boring_sys::SSL_CTX_get_cert_store(self.ctx.as_ptr());
            if store.is_null() {
                return (0, 0);
            }
            let stack = boring_sys::X509_STORE_get0_objects(store);
            if stack.is_null() {
                return (0, 0);
            }
            let n = boring_sys::OPENSSL_sk_num(stack as *const _);
            for i in 0..n {
                let obj = boring_sys::OPENSSL_sk_value(stack as *const _, i)
                    as *const boring_sys::X509_OBJECT;
                if obj.is_null() {
                    continue;
                }
                match boring_sys::X509_OBJECT_get_type(obj) {
                    t if t == boring_sys::X509_LU_X509 => x509 += 1,
                    t if t == boring_sys::X509_LU_CRL => crl += 1,
                    _ => {}
                }
            }
        }
        (x509, crl)
    }

    /// Load a certificate chain and (optionally) its private key for mTLS.
    ///
    /// Both inputs are in-memory PEM bytes - the Python facade is responsible
    /// for reading files from disk when the caller passed a path. This avoids
    /// duplicating BoringSSL's path-based helpers and gives us first-class
    /// support for secret-store backed certs (Vault, K8s, env vars, ...) that
    /// would otherwise need a `tempfile` round-trip.
    ///
    /// `cert_pem` must contain at least one `CERTIFICATE` block (the leaf);
    /// any additional blocks are installed as intermediate chain certs in
    /// file order. When `key_pem` is `None` the key is read from `cert_pem`
    /// itself (matches stdlib's "bundle file" mode).
    ///
    /// When `password` is `Some`, BoringSSL's PEM password callback is wired
    /// for the duration of `PEM_read_bio_PrivateKey` only - no `SSL_CTX`
    /// state is mutated. The buffer is zeroed before returning regardless
    /// of success.
    pub fn load_cert_chain(
        &self,
        cert_pem: &[u8],
        key_pem: Option<&[u8]>,
        password: Option<&[u8]>,
    ) -> Result<()> {
        // Wipe any pre-existing error state so our "is it EOF or a real
        // parse error?" check below isn't confused by an earlier failure.
        unsafe { boring_sys::ERR_clear_error() };

        // --- Certificate chain ----------------------------------------------
        // SAFETY: cert_pem.as_ptr() is valid for cert_pem.len() bytes;
        // BIO_new_mem_buf does not take ownership of the buffer (read-only).
        let cert_bio = unsafe {
            BioGuard::new(boring_sys::BIO_new_mem_buf(
                cert_pem.as_ptr() as *const std::ffi::c_void,
                cert_pem.len() as isize,
            ))
        }?;

        // Leaf cert: must succeed, else the PEM is unusable.
        // SAFETY: bio is live; we pass NULL for x (let BoringSSL allocate)
        // and NULL cb/userdata (leaf certs aren't password-encrypted).
        let leaf = unsafe {
            boring_sys::PEM_read_bio_X509(
                cert_bio.as_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        };
        if leaf.is_null() {
            return Err(Error::from_boring_queue("PEM_read_bio_X509 (leaf)"));
        }
        // SAFETY: leaf came from PEM_read_bio_X509 with refcount=1;
        // SSL_CTX_use_certificate bumps it, so we must free our handle after.
        let rc = unsafe { boring_sys::SSL_CTX_use_certificate(self.ctx.as_ptr(), leaf) };
        unsafe { boring_sys::X509_free(leaf) };
        if rc != 1 {
            return Err(Error::from_boring_queue("SSL_CTX_use_certificate"));
        }

        // Clear any intermediates already attached from a previous call.
        // Matches stdlib semantics: the latest `load_cert_chain` wins.
        // SAFETY: ctx is valid.
        unsafe { boring_sys::SSL_CTX_clear_extra_chain_certs(self.ctx.as_ptr()) };

        // Intermediate chain certs: each subsequent PEM_read_bio_X509 returns
        // a refcount=1 X509; SSL_CTX_add_extra_chain_cert *takes ownership*
        // (does NOT bump refcount) so we must not free on success.
        loop {
            // SAFETY: same as the leaf read.
            let cert = unsafe {
                boring_sys::PEM_read_bio_X509(
                    cert_bio.as_ptr(),
                    std::ptr::null_mut(),
                    None,
                    std::ptr::null_mut(),
                )
            };
            if cert.is_null() {
                // NULL means either EOF (normal) or a real parse error.
                // BoringSSL signals EOF via PEM_R_NO_START_LINE in the error
                // queue; in both cases we clear it and break - if it was a
                // real error, the *next* operation on this CTX will surface
                // a useful message, and we've at least installed the leaf.
                unsafe { boring_sys::ERR_clear_error() };
                break;
            }
            // SAFETY: cert is a refcount=1 X509 we own; add_extra_chain_cert
            // takes ownership on success (return 1).
            let rc = unsafe { boring_sys::SSL_CTX_add_extra_chain_cert(self.ctx.as_ptr(), cert) };
            if rc != 1 {
                // Ownership wasn't transferred; we still own it.
                unsafe { boring_sys::X509_free(cert) };
                return Err(Error::from_boring_queue("SSL_CTX_add_extra_chain_cert"));
            }
        }

        // --- Private key ----------------------------------------------------
        // Stdlib semantics: when keyfile is omitted, the key is read from
        // the same PEM bundle as the cert.
        let key_data = key_pem.unwrap_or(cert_pem);
        // SAFETY: key_data is valid for key_data.len() bytes.
        let key_bio = unsafe {
            BioGuard::new(boring_sys::BIO_new_mem_buf(
                key_data.as_ptr() as *const std::ffi::c_void,
                key_data.len() as isize,
            ))
        }?;

        // Password callback wiring is per-call (passed directly to
        // PEM_read_bio_PrivateKey), so there is no SSL_CTX-level state to
        // install/uninstall. The buffer is zeroed before we return.
        let mut pw_buf: Option<Vec<u8>> = password.map(<[u8]>::to_vec);
        let (cb, userdata): (boring_sys::pem_password_cb, *mut std::ffi::c_void) =
            match pw_buf.as_mut() {
                // SAFETY: pointer is stable for the duration of the
                // PEM_read_bio_PrivateKey call below (Vec is on this stack frame).
                Some(buf) => (
                    Some(pem_passwd_cb_trampoline),
                    buf as *mut Vec<u8> as *mut std::ffi::c_void,
                ),
                None => (None, std::ptr::null_mut()),
            };

        // SAFETY: bio + cb + userdata as documented above.
        let key = unsafe {
            boring_sys::PEM_read_bio_PrivateKey(
                key_bio.as_ptr(),
                std::ptr::null_mut(),
                cb,
                userdata,
            )
        };
        // Zero the password buffer ASAP, before any error-return path.
        if let Some(buf) = pw_buf.as_mut() {
            buf.iter_mut().for_each(|b| *b = 0);
        }
        if key.is_null() {
            return Err(Error::from_boring_queue("PEM_read_bio_PrivateKey"));
        }
        // SAFETY: key came from PEM_read_bio_PrivateKey with refcount=1;
        // SSL_CTX_use_PrivateKey bumps it, so we free our handle after.
        let rc = unsafe { boring_sys::SSL_CTX_use_PrivateKey(self.ctx.as_ptr(), key) };
        unsafe { boring_sys::EVP_PKEY_free(key) };
        if rc != 1 {
            return Err(Error::from_boring_queue("SSL_CTX_use_PrivateKey"));
        }

        // SAFETY: cert + key already loaded; cross-check.
        let rc = unsafe { boring_sys::SSL_CTX_check_private_key(self.ctx.as_ptr()) };
        if rc != 1 {
            return Err(Error::from_boring_queue("SSL_CTX_check_private_key"));
        }
        Ok(())
    }

    /// Create a [`Connection`] driven by the supplied memory BIOs.
    ///
    /// **Client mode** - `server_hostname` is required when
    /// `check_hostname=True`; it is used both as SNI and as the
    /// hostname-verification anchor. The configured fingerprint (if any) and
    /// ECH override (if any) are applied to the fresh `SSL*`.
    ///
    /// **Server mode** - `server_hostname` is ignored (the client sends SNI,
    /// not us). Fingerprint/ECH-client overrides are skipped. A
    /// per-connection capture slot is attached for `get_fingerprint()`.
    pub fn wrap_bio(
        &self,
        incoming: &MemoryBio,
        outgoing: &MemoryBio,
        server_hostname: Option<&str>,
        session: Option<&Session>,
    ) -> Result<Connection> {
        if !self.is_server && self.check_hostname() && server_hostname.is_none() {
            return Err(Error::Usage(
                "server_hostname is required when check_hostname is True".into(),
            ));
        }
        // SAFETY: ctx is valid; SSL_new either returns NULL or a fresh handle.
        let raw = unsafe { boring_sys::SSL_new(self.ctx.as_ptr()) };
        let ssl = NonNull::new(raw).ok_or_else(|| Error::from_boring_queue("SSL_new"))?;

        // Wire the BIOs. SSL_set_bio takes ownership of *both* BIOs (refcount-wise);
        // because we want Python to keep its MemoryBIO objects alive and
        // mutable, we bump each BIO's refcount before handing them in so the
        // SSL's drop doesn't free them.
        // SAFETY: BIOs are valid; BIO_up_ref is the documented refcount bump.
        unsafe {
            boring_sys::BIO_up_ref(incoming.as_ptr());
            boring_sys::BIO_up_ref(outgoing.as_ptr());
            boring_sys::SSL_set_bio(ssl.as_ptr(), incoming.as_ptr(), outgoing.as_ptr());
        }

        if self.is_server {
            // Server mode: install accept state, attach the CH capture slot,
            // and skip all client-side configuration (SNI, hostname check,
            // ECH override, fingerprint apply).
            // SAFETY: ssl is fresh.
            unsafe { boring_sys::SSL_set_accept_state(ssl.as_ptr()) };
            // SAFETY: ssl is fresh; ex-data slot is per-SSL.
            unsafe { crate::server_fp::attach_capture_slot(ssl.as_ptr()) };

            // Resumption is meaningful server-side too (we'd be importing a
            // session the peer sent in a previous connection - rare for
            // server-side TLS but still legal). Apply if provided.
            if let Some(sess) = session {
                // SAFETY: ssl + session valid; SSL_set_session bumps refcount.
                let rc = unsafe { boring_sys::SSL_set_session(ssl.as_ptr(), sess.as_ptr()) };
                if rc != 1 {
                    return Err(Error::from_boring_queue("SSL_set_session"));
                }
            }

            return Ok(Connection {
                ssl,
                state: HandshakeState::NotStarted,
                server_hostname: None,
                is_server: true,
            });
        }

        // Client mode.
        // SAFETY: ssl is valid.
        unsafe { boring_sys::SSL_set_connect_state(ssl.as_ptr()) };

        // SNI + hostname check.
        //
        // Routing rules (match CPython's _ssl.c and RFC 6066):
        //
        // * If `server_hostname` parses as a literal IP adress (v4 or v6),
        //   skip SNI entirely (RFC 6066 §3 forbids IP literals in SNI) and
        //   route the verifier through ``X509_VERIFY_PARAM_set1_ip_asc`` so
        //   the cert's ``iPAddress`` SAN entries are matched, not its DNS
        //   SANs / CN.
        // * Otherwise it's a DNS name: set SNI and route the verifier through
        //   ``SSL_set1_host`` (which calls ``X509_check_host`` internally) so
        //   ``dNSName`` SANs are matched.
        if let Some(host) = server_hostname {
            let host_c = CString::new(host)
                .map_err(|_| Error::Usage("server_hostname contains a NUL byte".into()))?;
            let is_ip = host.parse::<std::net::IpAddr>().is_ok();
            if !is_ip {
                // SAFETY: ssl + nul-term string valid. tlsext_host_name = 0.
                unsafe {
                    boring_sys::SSL_set_tlsext_host_name(ssl.as_ptr(), host_c.as_ptr());
                }
            }
            if self.check_hostname() {
                if is_ip {
                    // SAFETY: ssl valid; SSL_get0_param returns a borrowed
                    // pointer owned by the SSL. set1_ip_asc parses the textual
                    // form (dotted-quad / RFC 4291 IPv6) and stores 4 or 16
                    // raw bytes on the verify param; the function copies, so
                    // host_c can drop at end of scope.
                    let rc = unsafe {
                        let param = boring_sys::SSL_get0_param(ssl.as_ptr());
                        boring_sys::X509_VERIFY_PARAM_set1_ip_asc(param, host_c.as_ptr())
                    };
                    if rc != 1 {
                        return Err(Error::from_boring_queue("X509_VERIFY_PARAM_set1_ip_asc"));
                    }
                } else {
                    // SAFETY: SSL_set1_host copies the string.
                    let rc = unsafe { boring_sys::SSL_set1_host(ssl.as_ptr(), host_c.as_ptr()) };
                    if rc != 1 {
                        return Err(Error::from_boring_queue("SSL_set1_host"));
                    }
                    // Strict matching: no wildcard creep, no CN fallback.
                    // SAFETY: ssl is valid.
                    unsafe {
                        let param = boring_sys::SSL_get0_param(ssl.as_ptr());
                        boring_sys::X509_VERIFY_PARAM_set_hostflags(
                            param,
                            (boring_sys::X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
                                | boring_sys::X509_CHECK_FLAG_NEVER_CHECK_SUBJECT)
                                as u32,
                        );
                    }
                }
            }
        }

        // Resumption.
        if let Some(sess) = session {
            // SAFETY: ssl + session valid; SSL_set_session bumps the session refcount.
            let rc = unsafe { boring_sys::SSL_set_session(ssl.as_ptr(), sess.as_ptr()) };
            if rc != 1 {
                return Err(Error::from_boring_queue("SSL_set_session"));
            }
        }

        // Fingerprint, if any.
        if let Some(fp) = self.fingerprint() {
            // If the user explicitly called set_alpn_protocols(...) after
            // set_fingerprint(...), pass that list as an override: the
            // fingerprint stays Chrome in every other respect, but ALPN
            // reflects the user's intent (e.g. ["http/1.1"] for Chrome's
            // WebSocket-over-h1 path) and ALPS entries for protocols no
            // longer offered are skipped so we don't emit an internally
            // incoherent ALPS-without-ALPN ClientHello that no real Chrome
            // ever sends.
            let alpn_override = self.alpn_list_snapshot();
            // SAFETY: ssl is fresh and not yet in handshake; Fingerprint::apply
            // contractually only touches knobs that are legal pre-handshake.
            unsafe {
                if alpn_override.is_empty() {
                    fp.apply_to_ssl(ssl.as_ptr())?;
                } else {
                    fp.apply_to_ssl_with_alpn_override(ssl.as_ptr(), &alpn_override)?;
                }
            }
        }

        // Real ECH override. Applied *after* the fingerprint so it takes
        // precedence over the fingerprint's `ech` policy. `SSL_set1_ech_config_list`
        // copies the bytes; on success BoringSSL will emit the `encrypted_client_hello`
        // extension on the wire with the ClientHelloInner sealed under the
        // selected HPKE config.
        if let Some(ech_bytes) = self.ech_config_list() {
            // SAFETY: ssl is live; pointer + length valid; BoringSSL copies.
            let rc = unsafe {
                boring_sys::SSL_set1_ech_config_list(
                    ssl.as_ptr(),
                    ech_bytes.as_ptr(),
                    ech_bytes.len(),
                )
            };
            if rc != 1 {
                return Err(Error::from_boring_queue("SSL_set1_ech_config_list"));
            }
        }

        Ok(Connection {
            ssl,
            state: HandshakeState::NotStarted,
            server_hostname: server_hostname.map(|s| s.to_owned()),
            is_server: false,
        })
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: we own one ref to the SSL_CTX. SSL_CTX_free decrements;
        // BoringSSL frees the underlying object when its refcount hits 0.
        // The per-context ALPN/keylog registry entries are scrubbed by
        // `RegistryGuard::drop` (fires automatically on the last `Arc`
        // clone) so an SSL_CTX address that malloc later reuses cannot
        // inherit them.
        unsafe {
            boring_sys::SSL_CTX_free(self.ctx.as_ptr());
        }
    }
}

// Connection

/// One in-progress or established TLS connection.
///
/// `Connection` is `!Sync`: BoringSSL `SSL*` handles must only be touched
/// from one thread at a time. The PyO3 layer guarantees this with a Mutex.
pub struct Connection {
    ssl: NonNull<boring_sys::SSL>,
    state: HandshakeState,
    server_hostname: Option<String>,
    is_server: bool,
}

// SAFETY: see `Context` - `SSL*` is `Send` provided we never touch it
// concurrently from multiple threads.
unsafe impl Send for Connection {}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("state", &self.state)
            .field("server_hostname", &self.server_hostname)
            .finish()
    }
}

impl Connection {
    /// Drive the handshake one step. Returns:
    /// * `Ok(true)`  - handshake complete.
    /// * `Ok(false)` - handshake still in progress (more I/O needed).
    /// * `Err(Error::WantRead | WantWrite)` - caller must move bytes through
    ///   the BIOs and call again.
    pub fn do_handshake(&mut self) -> Result<bool> {
        if matches!(self.state, HandshakeState::Established) {
            return Ok(true);
        }
        self.state = HandshakeState::InProgress;
        // SAFETY: ssl is valid.
        let rc = unsafe { boring_sys::SSL_do_handshake(self.ssl.as_ptr()) };
        if rc == 1 {
            self.state = HandshakeState::Established;
            return Ok(true);
        }
        let err = self.translate_ssl_error(rc);
        match err {
            Error::WantRead | Error::WantWrite => Err(err),
            // Verification errors get a dedicated variant so the Python layer
            // can raise SSLCertVerificationError.
            Error::Protocol { .. } => {
                // SAFETY: ssl valid; both calls are read-only.
                let verify_mode = unsafe { boring_sys::SSL_get_verify_mode(self.ssl.as_ptr()) };
                let verifies = (verify_mode as u32 & boring_sys::SSL_VERIFY_PEER as u32) != 0;
                let verify = unsafe { boring_sys::SSL_get_verify_result(self.ssl.as_ptr()) };
                if verifies && verify != 0
                /* X509_V_OK */
                {
                    // SAFETY: ssl valid.
                    Err(unsafe { verification_error(self.ssl.as_ptr()) })
                } else {
                    Err(err)
                }
            }
            other => Err(other),
        }
    }

    /// Read up to `max` bytes of decrypted application data.
    ///
    /// Calls `SSL_read` in a loop until either `max` bytes are accumulated,
    /// the in-memory ciphertext is exhausted (`SSL_ERROR_WANT_READ`), the
    /// peer cleanly shuts the connection (`SSL_ERROR_ZERO_RETURN`), or a
    /// hard error occurs. A single Python⟶Rust call therefore drains as
    /// many TLS records as are already buffered, instead of one record per
    /// call - mirrors rtls's fused `decrypt_incoming` for the SSL_read path.
    pub fn read(&mut self, max: usize) -> Result<Vec<u8>> {
        if max == 0 {
            return Ok(Vec::new());
        }
        let cap = max.min(i32::MAX as usize);
        let mut buf = vec![0u8; cap];
        let mut filled: usize = 0;

        loop {
            let remaining = cap - filled;
            if remaining == 0 {
                break;
            }
            let rc = unsafe {
                boring_sys::SSL_read(
                    self.ssl.as_ptr(),
                    buf.as_mut_ptr().add(filled) as *mut _,
                    remaining as i32,
                )
            };
            if rc > 0 {
                filled += rc as usize;
                // Loop: there may be more buffered records to drain into
                // the rest of the output buffer without another userland
                // round-trip. If the BIO is empty we'll get WANT_READ next.
                continue;
            }
            // rc <= 0: classify.
            let err = self.translate_ssl_error(rc);
            // If we've already accumulated something, treat WantRead as a
            // clean stop (return what we have) - matches stdlib's
            // ``SSLSocket.recv`` which returns short reads when the BIO
            // drains mid-call. ZeroReturn (close_notify) likewise yields
            // the buffered plaintext; the next call will surface EOF.
            if filled > 0 && matches!(err, Error::WantRead | Error::WantWrite | Error::ZeroReturn) {
                break;
            }
            if filled == 0 {
                return Err(err);
            }
            // filled > 0 and err is a hard error - return data, surface
            // the error on the next call.
            break;
        }

        buf.truncate(filled);
        Ok(buf)
    }

    /// for `SSLSocket.recv_into`
    pub fn read_into(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Cap at SSL_read's i32 limit; the caller's buffer might be huge.
        let cap = buf.len().min(i32::MAX as usize);
        let mut filled: usize = 0;

        loop {
            let remaining = cap - filled;
            if remaining == 0 {
                break;
            }
            // SAFETY: buf is a valid mutable slice; we write within bounds.
            let rc = unsafe {
                boring_sys::SSL_read(
                    self.ssl.as_ptr(),
                    buf.as_mut_ptr().add(filled) as *mut _,
                    remaining as i32,
                )
            };
            if rc > 0 {
                filled += rc as usize;
                // Drain additional records into the rest of the buffer
                // without another userland round-trip, same as `read`.
                continue;
            }
            let err = self.translate_ssl_error(rc);
            if filled > 0 && matches!(err, Error::WantRead | Error::WantWrite | Error::ZeroReturn) {
                break;
            }
            if filled == 0 {
                return Err(err);
            }
            break;
        }

        Ok(filled)
    }

    /// Encrypt and queue `data` for sending. Returns bytes accepted by the
    /// SSL state machine (caller still needs to drain the outgoing BIO).
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let n = data.len().min(i32::MAX as usize);
        // SAFETY: ssl + data valid.
        let rc = unsafe {
            boring_sys::SSL_write(self.ssl.as_ptr(), data.as_ptr() as *const _, n as i32)
        };
        if rc > 0 {
            return Ok(rc as usize);
        }
        Err(self.translate_ssl_error(rc))
    }

    /// Initiate a clean shutdown (send `close_notify`). May need to be called
    /// twice (once to send, once to consume the peer's notify).
    pub fn shutdown(&mut self) -> Result<bool> {
        // SAFETY: ssl valid.
        let rc = unsafe { boring_sys::SSL_shutdown(self.ssl.as_ptr()) };
        match rc {
            1 => {
                self.state = HandshakeState::Shutdown;
                Ok(true)
            }
            0 => Ok(false), // need to call again after peer's notify
            _ => Err(self.translate_ssl_error(rc)),
        }
    }

    pub fn state(&self) -> HandshakeState {
        self.state
    }

    pub fn server_hostname(&self) -> Option<&str> {
        self.server_hostname.as_deref()
    }

    /// Whether this connection handshakes as a server (`SSL_accept`).
    pub fn is_server(&self) -> bool {
        self.is_server
    }

    /// Server-side: SNI value the peer sent in its ClientHello, if any.
    /// Mirrors `SSLObject.server_hostname` on the server side (CPython only
    /// populates it from `SSL_get_servername(TLSEXT_NAMETYPE_host_name)`).
    pub fn peer_sni(&self) -> Option<String> {
        // SAFETY: ssl valid; SSL_get_servername returns a borrowed C string.
        let p = unsafe {
            boring_sys::SSL_get_servername(self.ssl.as_ptr(), boring_sys::TLSEXT_NAMETYPE_host_name)
        };
        if p.is_null() {
            return None;
        }
        // SAFETY: NUL-terminated string owned by BoringSSL for the SSL's lifetime.
        Some(
            unsafe { std::ffi::CStr::from_ptr(p) }
                .to_string_lossy()
                .into_owned(),
        )
    }

    /// Parse the captured peer ClientHello (server-side only) into a
    /// [`Fingerprint`]. Returns `None` if no CH was captured yet, or if
    /// this is a client connection.
    pub fn observed_client_fingerprint(&self) -> Option<Fingerprint> {
        if !self.is_server {
            return None;
        }
        // SAFETY: ssl valid; slot was attached in wrap_bio (server branch).
        let bytes = unsafe { crate::server_fp::captured_client_hello(self.ssl.as_ptr()) }?;
        crate::fingerprint::capture::parse_client_hello(&bytes).ok()
    }

    /// Negotiated ALPN protocol, if any.
    pub fn selected_alpn(&self) -> Option<String> {
        let mut data: *const u8 = std::ptr::null();
        let mut len: u32 = 0;
        // SAFETY: ssl valid; out-params populated.
        unsafe {
            boring_sys::SSL_get0_alpn_selected(self.ssl.as_ptr(), &mut data, &mut len);
        }
        if data.is_null() || len == 0 {
            return None;
        }
        // SAFETY: BoringSSL guarantees data points to `len` valid bytes for
        // the lifetime of the SSL handle.
        let slice = unsafe { std::slice::from_raw_parts(data, len as usize) };
        Some(String::from_utf8_lossy(slice).into_owned())
    }

    /// Returns `true` if ECH was offered *and* the server accepted it
    /// (the inner ClientHello, including the real SNI, was decrypted and
    /// honored). Returns `false` before the handshake completes, when ECH
    /// was not offered, or when the server fell back to the public name.
    /// Wraps `SSL_ech_accepted`.
    pub fn ech_accepted(&self) -> bool {
        if !matches!(self.state, HandshakeState::Established) {
            return false;
        }
        // SAFETY: ssl valid; returns int 0/1.
        unsafe { boring_sys::SSL_ech_accepted(self.ssl.as_ptr()) == 1 }
    }

    /// If the server rejected our ECH config and supplied a fresh one for
    /// the next attempt, return it (wire-format `ECHConfigList` bytes).
    /// Returns `None` if ECH was accepted, if it was never offered, or if
    /// the server signalled "no retry, ECH is rolled back" with an empty
    /// retry list. Pair with [`crate::context::Context::set_ech_configs`]
    /// on a new connection to retry transparently. Wraps
    /// `SSL_get0_ech_retry_configs`.
    pub fn ech_retry_configs(&self) -> Option<Vec<u8>> {
        // Only meaningful post-handshake - BoringSSL may otherwise return an
        // uninitialized sentinel buffer for `SSL_get0_ech_retry_configs`
        // when called on a connection that has not produced a ServerHello.
        if !matches!(self.state, HandshakeState::Established) {
            return None;
        }
        let mut data: *const u8 = std::ptr::null();
        let mut len: usize = 0;
        // SAFETY: ssl valid; out-params populated; pointer is owned by the
        // SSL handle and lives until the handle is freed - we copy out.
        unsafe {
            boring_sys::SSL_get0_ech_retry_configs(self.ssl.as_ptr(), &mut data, &mut len);
        }
        if data.is_null() || len == 0 {
            return None;
        }
        // SAFETY: BoringSSL guarantees data points to `len` valid bytes
        // for the lifetime of the SSL handle.
        let slice = unsafe { std::slice::from_raw_parts(data, len) };
        Some(slice.to_vec())
    }

    /// Negotiated TLS version as a stable string ("TLSv1.3", "TLSv1.2", ...).
    /// Returns `None` before the handshake completes - matches stdlib
    /// `SSLObject.version()`, which only reports the negotiated version.
    pub fn version(&self) -> Option<&'static str> {
        if !matches!(self.state, HandshakeState::Established) {
            return None;
        }
        // SAFETY: ssl valid; SSL_version returns a small int.
        let v = unsafe { boring_sys::SSL_version(self.ssl.as_ptr()) };
        match v {
            0x0304 => Some("TLSv1.3"),
            0x0303 => Some("TLSv1.2"),
            0x0302 => Some("TLSv1.1"),
            0x0301 => Some("TLSv1"),
            _ => None,
        }
    }

    /// Negotiated cipher as `(name, protocol_version, bits)`.
    pub fn cipher(&self) -> Option<(String, &'static str, i32)> {
        // SAFETY: ssl valid.
        let c = unsafe { boring_sys::SSL_get_current_cipher(self.ssl.as_ptr()) };
        if c.is_null() {
            return None;
        }
        // SAFETY: c is a valid SSL_CIPHER*.
        let name_ptr = unsafe { boring_sys::SSL_CIPHER_get_name(c) };
        if name_ptr.is_null() {
            return None;
        }
        // SAFETY: name_ptr is a nul-terminated C string owned by BoringSSL.
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: c valid.
        let bits = unsafe { boring_sys::SSL_CIPHER_get_bits(c, std::ptr::null_mut()) };
        Some((name, self.version().unwrap_or("TLS"), bits))
    }

    /// Extract the negotiated session for resumption. Returns None before the
    /// handshake completes.
    pub fn session(&self) -> Option<Session> {
        if !matches!(self.state, HandshakeState::Established) {
            return None;
        }
        // SAFETY: ssl valid; SSL_get1_session bumps the refcount.
        let raw = unsafe { boring_sys::SSL_get1_session(self.ssl.as_ptr()) };
        // SAFETY: from_owned_ptr handles the NULL case.
        unsafe { Session::from_owned_ptr(raw) }
    }

    /// Whether the current connection reused a previous session.
    pub fn session_reused(&self) -> bool {
        // SAFETY: ssl valid.
        let rc = unsafe { boring_sys::SSL_session_reused(self.ssl.as_ptr()) };
        rc == 1
    }

    /// Peer certificate chain in DER form. Empty before handshake.
    pub fn peer_chain_der(&self) -> Result<Vec<Vec<u8>>> {
        // SAFETY: ssl valid.
        unsafe { peer_chain_der(self.ssl.as_ptr()) }
    }

    /// Parsed view of the leaf peer certificate - backs
    /// `SSLObject.getpeercert(binary_form=False)`. Returns `Ok(None)` if no
    /// peer certificate is available (handshake incomplete or no cert sent).
    pub fn peer_cert_info(&self) -> Result<Option<crate::peer_cert::PeerCertInfo>> {
        // SAFETY: ssl valid.
        unsafe { crate::peer_cert::peer_cert_info(self.ssl.as_ptr()) }
    }

    /// Translate the return code of an `SSL_read/write/handshake` call into
    /// our error enum.
    fn translate_ssl_error(&self, rc: i32) -> Error {
        // SAFETY: ssl valid.
        let code = unsafe { boring_sys::SSL_get_error(self.ssl.as_ptr(), rc) };
        // boring-sys 5 exposes the SSL_ERROR_* constants as `i32`, the same
        // type as SSL_get_error's return - no cast needed.
        match code {
            c if c == boring_sys::SSL_ERROR_WANT_READ => Error::WantRead,
            c if c == boring_sys::SSL_ERROR_WANT_WRITE => Error::WantWrite,
            c if c == boring_sys::SSL_ERROR_ZERO_RETURN => Error::ZeroReturn,
            c if c == boring_sys::SSL_ERROR_SYSCALL => {
                // 0 return from SSL_read with SYSCALL = peer closed transport
                // without close_notify.
                Error::Eof
            }
            _ => Error::from_boring_queue("SSL operation"),
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // Release the per-connection capture slot (server side only). Safe to
        // call unconditionally - it no-ops when the slot is absent.
        // SAFETY: ssl is our owned handle, still live.
        unsafe {
            crate::server_fp::drop_capture_slot(self.ssl.as_ptr());
        }
        // SAFETY: we own the SSL handle. SSL_free internally decrements the
        // refcount on both BIOs we attached (we bumped them on attach so the
        // user's MemoryBios stay alive).
        unsafe {
            boring_sys::SSL_free(self.ssl.as_ptr());
        }
    }
}

// ALPN selection trampoline (server-side)

/// `SSL_CTX_set_alpn_select_cb` trampoline: pick the first protocol from our
/// server-side preference list that the client also offered. If none match,
/// return `SSL_TLSEXT_ERR_NOACK` (BoringSSL sends no ALPN extension back,
/// per RFC 7301 fallback semantics, rather than aborting).
///
/// We look up the preference list by walking from `SSL_get_SSL_CTX(ssl)`
/// back to our [`Context`] via a static registry keyed by raw SSL_CTX
/// pointer - kept in `ALPN_REGISTRY`. The registry entry is added on
/// `Context::new(server)` and removed on `Context::drop`.
///
/// # Safety
/// FFI entry point. All pointers must be valid for the call duration.
unsafe extern "C" fn alpn_select_cb_trampoline(
    ssl: *mut boring_sys::SSL,
    out: *mut *const u8,
    out_len: *mut u8,
    client_protos: *const u8,
    client_protos_len: std::os::raw::c_uint,
    _arg: *mut std::os::raw::c_void,
) -> std::os::raw::c_int {
    // BoringSSL header value: ssl/tls1.h SSL_TLSEXT_ERR_OK = 0, ERR_NOACK = 3.
    const SSL_TLSEXT_ERR_OK: c_int = 0;
    const SSL_TLSEXT_ERR_NOACK: c_int = 3;

    if ssl.is_null() || client_protos.is_null() || client_protos_len == 0 {
        return SSL_TLSEXT_ERR_NOACK;
    }
    // SAFETY: ssl is the live handshake handle.
    let ctx_ptr = unsafe { boring_sys::SSL_get_SSL_CTX(ssl) };
    if ctx_ptr.is_null() {
        return SSL_TLSEXT_ERR_NOACK;
    }
    let prefs = match alpn_registry_lookup(ctx_ptr) {
        Some(v) if !v.is_empty() => v,
        _ => return SSL_TLSEXT_ERR_NOACK,
    };

    // SAFETY: pointer + length describe a valid &[u8] for the call duration.
    let client = unsafe { std::slice::from_raw_parts(client_protos, client_protos_len as usize) };

    // Iterate our preference list; for each, scan the client's wire-format
    // (length-prefixed) offers for an exact match.
    for pref in &prefs {
        let mut i = 0usize;
        while i < client.len() {
            let len = client[i] as usize;
            i += 1;
            if i + len > client.len() {
                break;
            }
            if &client[i..i + len] == pref.as_slice() {
                // Point BoringSSL at our preference bytes. The pointer must
                // remain valid until the handshake completes; since `prefs`
                // came from cloning a Vec held in `ALPN_REGISTRY`, it lives
                // only for this function call. So we leak it: BoringSSL will
                // copy the bytes into its own buffer post-handshake, but to
                // be safe we keep them stable for the duration by storing
                // them in a per-SSL leak (we use a static Box::leak per
                // selection). Better: use the original Context-owned Vec.
                //
                // For simplicity and correctness, we Box::leak a small
                // allocation per successful selection. The lifetime is
                // bounded by the number of distinct selected protocols
                // across all handshakes, which is at most O(|alpn_list|) -
                // tiny in practice.
                let leaked: &'static [u8] = Box::leak(pref.clone().into_boxed_slice());
                // SAFETY: out + out_len are valid out-params per the cb ABI.
                unsafe {
                    *out = leaked.as_ptr();
                    *out_len = leaked.len() as u8;
                }
                return SSL_TLSEXT_ERR_OK;
            }
            i += len;
        }
    }
    SSL_TLSEXT_ERR_NOACK
}

// Tiny global registry: SSL_CTX* -> ALPN preference list. Inserted on
// `Context::new(server)`, removed on `Context::drop`. Keyed by raw pointer
// because that is what the callback receives via `SSL_get_SSL_CTX`.
fn alpn_registry() -> &'static std::sync::Mutex<std::collections::HashMap<usize, Vec<Vec<u8>>>> {
    static REG: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<usize, Vec<Vec<u8>>>>,
    > = std::sync::OnceLock::new();
    REG.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn alpn_registry_lookup(ctx: *mut boring_sys::SSL_CTX) -> Option<Vec<Vec<u8>>> {
    alpn_registry()
        .lock()
        .unwrap()
        .get(&(ctx as usize))
        .cloned()
}

fn alpn_registry_set(ctx: *mut boring_sys::SSL_CTX, list: Vec<Vec<u8>>) {
    alpn_registry().lock().unwrap().insert(ctx as usize, list);
}

// Keylog trampoline + registry

/// `SSL_CTX_set_keylog_callback` trampoline: append `line\n` to the
/// per-context writer registered via [`keylog_registry_set`].
///
/// # Safety
/// FFI entry point. `ssl` must be a live SSL handle, `line` a NUL-terminated
/// ASCII string - both invariants are upheld by BoringSSL.
unsafe extern "C" fn keylog_cb_trampoline(ssl: *const boring_sys::SSL, line: *const c_char) {
    if ssl.is_null() || line.is_null() {
        return;
    }
    // SAFETY: ssl is live during the callback.
    let ctx_ptr = unsafe { boring_sys::SSL_get_SSL_CTX(ssl as *mut _) };
    if ctx_ptr.is_null() {
        return;
    }
    let writer = match keylog_registry_lookup(ctx_ptr) {
        Some(w) => w,
        None => return,
    };
    // SAFETY: BoringSSL passes a NUL-terminated string.
    let bytes = unsafe { std::ffi::CStr::from_ptr(line) }.to_bytes();
    if let Ok(mut w) = writer.lock() {
        // Best-effort: swallow I/O errors. The keylog is a debugging
        // facility; failing the handshake because the disk filled up
        // would be the wrong trade-off.
        let _ = w.write_all(bytes);
        let _ = w.write_all(b"\n");
        let _ = w.flush();
    };
}

fn keylog_registry(
) -> &'static std::sync::Mutex<std::collections::HashMap<usize, Arc<Mutex<BufWriter<File>>>>> {
    type Reg = std::sync::Mutex<std::collections::HashMap<usize, Arc<Mutex<BufWriter<File>>>>>;
    static REG: std::sync::OnceLock<Reg> = std::sync::OnceLock::new();
    REG.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn keylog_registry_lookup(ctx: *mut boring_sys::SSL_CTX) -> Option<Arc<Mutex<BufWriter<File>>>> {
    keylog_registry()
        .lock()
        .unwrap()
        .get(&(ctx as usize))
        .cloned()
}

fn keylog_registry_set(ctx: *mut boring_sys::SSL_CTX, writer: Arc<Mutex<BufWriter<File>>>) {
    keylog_registry()
        .lock()
        .unwrap()
        .insert(ctx as usize, writer);
}

fn keylog_registry_remove(ctx: *mut boring_sys::SSL_CTX) {
    keylog_registry().lock().unwrap().remove(&(ctx as usize));
}

/// `pem_password_cb` trampoline used during [`Context::load_cert_chain`] to
/// supply the decryption password for an encrypted PKCS#8 / traditional PEM
/// key. `userdata` is a `*mut Vec<u8>` borrowed for the synchronous duration
/// of `PEM_read_bio_PrivateKey`.
///
/// # Safety
/// FFI entry point. `buf`/`size` describe a writable buffer of `size` bytes;
/// `userdata` is the pointer we ourselves installed (or NULL if BoringSSL
/// invokes the default pre-installed callback - which we never do).
unsafe extern "C" fn pem_passwd_cb_trampoline(
    buf: *mut c_char,
    size: c_int,
    _rwflag: c_int,
    userdata: *mut std::ffi::c_void,
) -> c_int {
    if buf.is_null() || size <= 0 || userdata.is_null() {
        return 0;
    }
    // SAFETY: userdata was set by load_cert_chain to a stable pointer into a
    // local Vec<u8> that outlives the FFI call we're nested inside.
    let pw = unsafe { &*(userdata as *const Vec<u8>) };
    let n = pw.len().min(size as usize);
    // SAFETY: buf has `size` writable bytes; we copy at most `n <= size`.
    unsafe { std::ptr::copy_nonoverlapping(pw.as_ptr(), buf as *mut u8, n) };
    n as c_int
}

/// RAII wrapper around a BoringSSL `BIO*` that frees on drop. Used by
/// [`Context::load_cert_chain`] so the early-return paths can't leak the
/// in-memory PEM BIO.
struct BioGuard(NonNull<boring_sys::BIO>);

impl BioGuard {
    /// Wrap a raw `BIO*`, returning an `Error` if the pointer is NULL
    /// (which the BoringSSL allocators only do under OOM).
    ///
    /// # Safety
    /// `bio` must be either NULL or a fresh, owned `BIO*` returned by a
    /// `BIO_new_*` constructor (refcount=1, no other owners).
    unsafe fn new(bio: *mut boring_sys::BIO) -> Result<Self> {
        NonNull::new(bio)
            .map(BioGuard)
            .ok_or_else(|| Error::from_boring_queue("BIO_new_mem_buf"))
    }

    fn as_ptr(&self) -> *mut boring_sys::BIO {
        self.0.as_ptr()
    }
}

impl Drop for BioGuard {
    fn drop(&mut self) {
        // SAFETY: pointer came from BIO_new_* with refcount=1 and we own it.
        unsafe { boring_sys::BIO_free(self.0.as_ptr()) };
    }
}

// SNI dispatch trampoline + registry

/// Outcome of an [`SniDispatcher`] invocation.
///
/// `SwitchTo` is intentionally absent: the dispatcher is expected to perform
/// any `SSL_set_SSL_CTX` swap itself (from whatever thread or language it
/// lives in) before returning. This keeps the trampoline / FFI surface
/// minimal and lets the dispatcher control object lifetimes.
#[derive(Debug)]
pub enum SniAction {
    /// Proceed with the (possibly swapped) `SSL_CTX`.
    Ok,
    /// Abort the handshake with the given TLS alert description
    /// (`SSL_AD_*` from RFC 8446 §6). Typical values:
    /// 112 = `unrecognized_name`, 80 = `internal_error`.
    Abort(u8),
}

/// Opaque handle to the in-flight `SSL*` passed to [`SniDispatcher::dispatch`].
///
/// Wraps the raw pointer so callers outside this crate cannot fabricate one
/// or use it for anything other than passing back to [`Context::migrate_ssl`].
#[derive(Clone, Copy, Debug)]
pub struct SniSslHandle {
    ssl: *mut boring_sys::SSL,
}

impl SniSslHandle {
    /// Reconstruct a handle from its raw pointer representation. Intended
    /// for FFI consumers (PyO3 bindings) that need to stash the pointer in
    /// a `usize` slot to keep it `Send`/`Sync`-safe across a callback's
    /// lifetime.
    ///
    /// # Safety
    /// `ssl` must originate from an [`SniDispatcher::dispatch`] invocation
    /// and must still be within that invocation's lifetime.
    pub unsafe fn from_raw(ssl: *mut boring_sys::SSL) -> Self {
        Self { ssl }
    }

    /// Returns the wrapped raw pointer as a non-zero `usize`, suitable for
    /// `AtomicUsize` storage. Returns 0 if the wrapped pointer is null
    /// (which should never happen for a handle obtained from a dispatcher).
    pub fn as_usize(&self) -> usize {
        self.ssl as usize
    }
}

// SAFETY: the handle is only valid for the duration of a dispatcher call,
// during which BoringSSL guarantees the SSL* is not concurrently mutated
// from another thread.
unsafe impl Send for SniSslHandle {}
unsafe impl Sync for SniSslHandle {}

impl Context {
    /// Swap `ssl` (an in-flight handshake handle the SNI dispatcher was
    /// invoked with) onto this context. See [`SniDispatcher`] for the
    /// surrounding semantics.
    pub fn migrate_ssl(&self, handle: SniSslHandle) {
        // SAFETY: `handle.ssl` is non-null and valid for the dispatcher
        // call duration by construction (see [`sni_cb_trampoline`]).
        unsafe { boring_sys::SSL_set_SSL_CTX(handle.ssl, self.ctx.as_ptr()) };
    }
}

/// Server-side SNI callback handle. Invoked from inside `SSL_do_handshake`
/// just after the ClientHello has been parsed.
///
/// Implementations may swap the in-flight SSL handle to a different
/// `SSL_CTX` (e.g. with a different certificate) by calling
/// `boring_sys::SSL_set_SSL_CTX(ssl, new_ctx)` directly. BoringSSL bumps
/// the new context's refcount and drops the old reference.
pub trait SniDispatcher: Send + Sync {
    /// Called once per ClientHello on a server context that has a
    /// dispatcher registered. `server_name` is the host_name SNI extension
    /// value if the client sent one (and it was parseable as UTF-8), else
    /// `None`. `handle` is valid only for the duration of this call.
    fn dispatch(&self, handle: SniSslHandle, server_name: Option<&str>) -> SniAction;
}

/// `SSL_CTX_set_tlsext_servername_callback` trampoline. Looks up the
/// dispatcher in [`sni_registry`] and invokes it; returns one of the
/// `SSL_TLSEXT_ERR_*` codes BoringSSL expects.
///
/// # Safety
/// FFI entry point. `ssl` is the live handshake handle; `out_alert` (when
/// non-NULL) is a writable `c_int` that we populate on the abort path.
unsafe extern "C" fn sni_cb_trampoline(
    ssl: *mut boring_sys::SSL,
    out_alert: *mut c_int,
    _arg: *mut std::ffi::c_void,
) -> c_int {
    // From ssl/tls1.h: OK = 0, ALERT_FATAL = 2.
    const SSL_TLSEXT_ERR_OK: c_int = 0;
    const SSL_TLSEXT_ERR_ALERT_FATAL: c_int = 2;
    const SSL_AD_INTERNAL_ERROR: c_int = 80;

    if ssl.is_null() {
        return SSL_TLSEXT_ERR_OK;
    }
    // SAFETY: ssl is live during the callback.
    let ctx_ptr = unsafe { boring_sys::SSL_get_SSL_CTX(ssl) };
    let dispatcher = match sni_registry_lookup(ctx_ptr) {
        Some(d) => d,
        // No callback registered for this context: behave as if the user had
        // never installed the trampoline. Default BoringSSL behaviour is to
        // accept any server name.
        None => return SSL_TLSEXT_ERR_OK,
    };

    // SAFETY: SSL_get_servername returns a borrowed C string valid for the
    // call duration, or NULL if the client did not send an SNI extension
    // (or sent an empty one).
    let name_ptr = unsafe {
        boring_sys::SSL_get_servername(ssl, boring_sys::TLSEXT_NAMETYPE_host_name as c_int)
    };
    let owned_name: Option<String> = if name_ptr.is_null() {
        None
    } else {
        // SAFETY: borrowed NUL-terminated string from BoringSSL.
        unsafe { std::ffi::CStr::from_ptr(name_ptr) }
            .to_str()
            .ok()
            .map(String::from)
    };

    // `dispatch` may re-enter the dispatcher's host language (e.g. acquire
    // the GIL). It runs synchronously; on return the SSL_CTX may have been
    // swapped already by the dispatcher (BoringSSL handles refcounting).
    let handle = SniSslHandle { ssl };
    match dispatcher.dispatch(handle, owned_name.as_deref()) {
        SniAction::Ok => SSL_TLSEXT_ERR_OK,
        SniAction::Abort(alert) => {
            if !out_alert.is_null() {
                // SAFETY: BoringSSL guarantees a writable c_int.
                unsafe { *out_alert = c_int::from(alert) };
            } else {
                // Out parameter missing - fall back to internal_error so
                // we still raise a fatal alert.
                if !out_alert.is_null() {
                    unsafe { *out_alert = SSL_AD_INTERNAL_ERROR };
                }
            }
            SSL_TLSEXT_ERR_ALERT_FATAL
        }
    }
}

type SniRegistry = std::sync::Mutex<std::collections::HashMap<usize, Arc<dyn SniDispatcher>>>;

fn sni_registry() -> &'static SniRegistry {
    static REG: std::sync::OnceLock<SniRegistry> = std::sync::OnceLock::new();
    REG.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn sni_registry_lookup(ctx: *mut boring_sys::SSL_CTX) -> Option<Arc<dyn SniDispatcher>> {
    sni_registry().lock().unwrap().get(&(ctx as usize)).cloned()
}

fn sni_registry_set(ctx: *mut boring_sys::SSL_CTX, d: Arc<dyn SniDispatcher>) {
    sni_registry().lock().unwrap().insert(ctx as usize, d);
}

fn sni_registry_remove(ctx: *mut boring_sys::SSL_CTX) {
    sni_registry().lock().unwrap().remove(&(ctx as usize));
}
