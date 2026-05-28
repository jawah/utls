//! Fingerprint subsystem.
//!
//! This module owns everything related to controlling the ClientHello:
//!
//! * [`spec::Fingerprint`]  - the declarative spec (cipher list, ext order,
//!   key shares, sigalgs, ALPN, ALPS, GREASE, padding, ECH, etc.).
//! * [`apply`]              - applies a spec to a live `SSL*` handle.
//! * [`capture`]            - parses a raw ClientHello back into a spec.
//! * [`ja3`] / [`ja4`]      - fingerprint hash algorithms; JA4 pinned.
//!
//! The split between *spec* (data) and *apply* (mutation) is deliberate:
//! the spec is cheap to clone, serialize, hash, and reason about; only the
//! per-connection `wrap_bio` path ever calls `apply`.

pub mod apply;
pub mod capture;
pub mod ja3;
pub mod ja4;
pub mod spec;

pub use spec::{Fingerprint, FingerprintBuilder};
