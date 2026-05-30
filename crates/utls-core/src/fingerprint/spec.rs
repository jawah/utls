//! Declarative ClientHello specification.
//!
//! A [`Fingerprint`] is *data*. It carries everything we need to reconstruct
//! a target browser's ClientHello byte sequence:
//!
//! * `cipher_suites`         - IANA cipher suite codepoints, in the order
//!   they appear in the ClientHello's cipher list.
//! * `extensions_order`      - IANA extension codepoints in the order they
//!   appear on the wire. Includes pseudo-codepoint
//!   [`GREASE_EXTENSION`] for the GREASE-typed
//!   extension placeholder.
//! * `supported_groups`      - codepoints for the `supported_groups` extension.
//! * `key_shares`            - subset of `supported_groups` for which we
//!   actually generate a key share.
//! * `signature_algorithms`  - codepoints for `signature_algorithms`.
//! * `alpn`                  - ALPN protocol IDs in order.
//! * `alps`                  - ALPS (application_settings) protocol IDs.
//! * `compress_certificate`  - `compress_certificate` algorithm names ("brotli", "zlib", "zstd").
//! * `record_size_limit`     - value for `record_size_limit` if present.
//! * `grease`                - whether to interleave GREASE values.
//! * `ech`                   - `false`, `true` (offer GREASE ECH), or `bytes` (offer real ECH config).
//! * `padding`               - fixed extension-padding target length, or None.

use std::collections::BTreeMap;

/// IANA codepoint reserved by this crate to mean "insert a GREASE-typed
/// extension placeholder here". GREASE codepoints proper are 0x?A?A; we
/// pick `0xFFFE` as a private-use sentinel that cannot collide.
pub const GREASE_EXTENSION: u16 = 0xFFFE;

/// A complete ClientHello specification.
///
/// Cloning is cheap (a few small Vecs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub cipher_suites: Vec<u16>,
    pub extensions_order: Vec<u16>,
    /// If `true`, BoringSSL randomly permutes the ClientHello extension
    /// order on every handshake (matches Chrome 110+ behaviour and keeps
    /// the JA4 hash stable while JA4_r varies). If `false`, BoringSSL
    /// emits its built-in static order. The `extensions_order` field is
    /// advisory metadata; it informs JA3/JA4 hashing but does not force
    /// the wire order.
    pub permute_extensions: bool,
    pub supported_groups: Vec<u16>,
    pub key_shares: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub alpn: Vec<String>,
    pub alps: Vec<String>,
    /// Which ALPS extension codepoint to emit on the wire:
    /// * `true` (default) -> new codepoint `0x44CD` (17613), used by
    ///   Chrome 124+ and the BoringSSL default.
    /// * `false` -> legacy codepoint `0x4469` (17513), used by Chrome
    ///   109-123. Wired via `SSL_set_alps_use_new_codepoint`.
    pub alps_use_new_codepoint: bool,
    pub compress_certificate: Vec<CertCompressAlg>,
    pub record_size_limit: Option<u16>,
    pub grease: bool,
    pub ech: EchPolicy,
    pub padding: Option<usize>,
}

/// Certificate-compression algorithm IDs we know how to assert in the
/// ClientHello. Mapping to wire codepoints:
///
/// * `Zlib`   -> 1
/// * `Brotli` -> 2
/// * `Zstd`   -> 3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertCompressAlg {
    Zlib,
    Brotli,
    Zstd,
}

impl CertCompressAlg {
    pub fn codepoint(self) -> u16 {
        match self {
            CertCompressAlg::Zlib => 1,
            CertCompressAlg::Brotli => 2,
            CertCompressAlg::Zstd => 3,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "zlib" => Some(CertCompressAlg::Zlib),
            "brotli" => Some(CertCompressAlg::Brotli),
            "zstd" => Some(CertCompressAlg::Zstd),
            _ => None,
        }
    }
}

/// Encrypted Client Hello policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EchPolicy {
    /// Don't include the `encrypted_client_hello` extension.
    Off,
    /// Include a GREASE'd ECH extension (no real config).
    Grease,
    /// Include a real ECH config (DER-encoded `ECHConfigList`).
    Real(Vec<u8>),
}

impl Default for Fingerprint {
    fn default() -> Self {
        Self {
            cipher_suites: Vec::new(),
            extensions_order: Vec::new(),
            permute_extensions: true,
            supported_groups: Vec::new(),
            key_shares: Vec::new(),
            signature_algorithms: Vec::new(),
            alpn: Vec::new(),
            alps: Vec::new(),
            alps_use_new_codepoint: true,
            compress_certificate: Vec::new(),
            record_size_limit: None,
            grease: true,
            ech: EchPolicy::Off,
            padding: None,
        }
    }
}

impl Fingerprint {
    /// Construct via the builder.
    pub fn builder() -> FingerprintBuilder {
        FingerprintBuilder::default()
    }

    /// Apply this fingerprint to a fresh `SSL*` handle. The handle must not
    /// have started its handshake yet.
    ///
    /// # Safety
    ///
    /// `ssl` must be a non-null, live `*mut SSL` not yet in handshake.
    pub unsafe fn apply_to_ssl(&self, ssl: *mut boring_sys::SSL) -> crate::error::Result<()> {
        // SAFETY: contract delegated to caller.
        unsafe { super::apply::apply(self, ssl, None) }
    }

    /// Same as [`Self::apply_to_ssl`], but caller-supplied `alpn_override`
    /// replaces the fingerprint's ALPN list for both the wire ALPN extension
    /// and the ALPS gating. Pass `Some(&list)` when the user explicitly
    /// called `SSLContext.set_alpn_protocols(...)` after `set_fingerprint(...)`:
    /// the fingerprint stays Chrome in every other respect, but ALPN reflects
    /// the user's intent and ALPS entries for protocols no longer offered
    /// are skipped so the ClientHello stays internally coherent (Chrome
    /// never sends ALPS for an ALPN protocol it didn't also offer).
    ///
    /// # Safety
    ///
    /// `ssl` must be a non-null, live `*mut SSL` not yet in handshake.
    pub unsafe fn apply_to_ssl_with_alpn_override(
        &self,
        ssl: *mut boring_sys::SSL,
        alpn_override: &[Vec<u8>],
    ) -> crate::error::Result<()> {
        // SAFETY: contract delegated to caller.
        unsafe { super::apply::apply(self, ssl, Some(alpn_override)) }
    }

    /// Convert to a key/value map for Python's `Fingerprint.to_dict()`.
    pub fn to_btreemap(&self) -> BTreeMap<&'static str, FpValue> {
        use FpValue::*;
        let mut m = BTreeMap::new();
        m.insert("cipher_suites", U16Vec(self.cipher_suites.clone()));
        m.insert("extensions_order", U16Vec(self.extensions_order.clone()));
        m.insert("supported_groups", U16Vec(self.supported_groups.clone()));
        m.insert("key_shares", U16Vec(self.key_shares.clone()));
        m.insert(
            "signature_algorithms",
            U16Vec(self.signature_algorithms.clone()),
        );
        m.insert("alpn", StringVec(self.alpn.clone()));
        m.insert("alps", StringVec(self.alps.clone()));
        m.insert("alps_use_new_codepoint", Bool(self.alps_use_new_codepoint));
        m.insert(
            "compress_certificate",
            StringVec(
                self.compress_certificate
                    .iter()
                    .map(|c| match c {
                        CertCompressAlg::Zlib => "zlib".into(),
                        CertCompressAlg::Brotli => "brotli".into(),
                        CertCompressAlg::Zstd => "zstd".into(),
                    })
                    .collect(),
            ),
        );
        m.insert("record_size_limit", OptU16(self.record_size_limit));
        m.insert("grease", Bool(self.grease));
        m.insert("permute_extensions", Bool(self.permute_extensions));
        m.insert(
            "ech",
            match &self.ech {
                EchPolicy::Off => Str("off".into()),
                EchPolicy::Grease => Str("grease".into()),
                EchPolicy::Real(b) => Bytes(b.clone()),
            },
        );
        m.insert("padding", OptUsize(self.padding));
        m
    }
}

/// Value type for the dict-shaped representation of a Fingerprint.
#[derive(Debug, Clone)]
pub enum FpValue {
    U16Vec(Vec<u16>),
    StringVec(Vec<String>),
    OptU16(Option<u16>),
    OptUsize(Option<usize>),
    Bool(bool),
    Str(String),
    Bytes(Vec<u8>),
}

/// Builder. Every field is independently optional, matching the Python
/// constructor's keyword-only-with-defaults shape.
#[derive(Debug, Default)]
pub struct FingerprintBuilder(Fingerprint);

impl FingerprintBuilder {
    pub fn cipher_suites(mut self, v: Vec<u16>) -> Self {
        self.0.cipher_suites = v;
        self
    }
    pub fn extensions_order(mut self, v: Vec<u16>) -> Self {
        self.0.extensions_order = v;
        self
    }
    pub fn permute_extensions(mut self, v: bool) -> Self {
        self.0.permute_extensions = v;
        self
    }
    pub fn supported_groups(mut self, v: Vec<u16>) -> Self {
        self.0.supported_groups = v;
        self
    }
    pub fn key_shares(mut self, v: Vec<u16>) -> Self {
        self.0.key_shares = v;
        self
    }
    pub fn signature_algorithms(mut self, v: Vec<u16>) -> Self {
        self.0.signature_algorithms = v;
        self
    }
    pub fn alpn(mut self, v: Vec<String>) -> Self {
        self.0.alpn = v;
        self
    }
    pub fn alps(mut self, v: Vec<String>) -> Self {
        self.0.alps = v;
        self
    }
    pub fn alps_use_new_codepoint(mut self, v: bool) -> Self {
        self.0.alps_use_new_codepoint = v;
        self
    }
    pub fn compress_certificate(mut self, v: Vec<CertCompressAlg>) -> Self {
        self.0.compress_certificate = v;
        self
    }
    pub fn record_size_limit(mut self, v: Option<u16>) -> Self {
        self.0.record_size_limit = v;
        self
    }
    pub fn grease(mut self, v: bool) -> Self {
        self.0.grease = v;
        self
    }
    pub fn ech(mut self, v: EchPolicy) -> Self {
        self.0.ech = v;
        self
    }
    pub fn padding(mut self, v: Option<usize>) -> Self {
        self.0.padding = v;
        self
    }
    pub fn build(self) -> Fingerprint {
        self.0
    }
}
