//! Build-time guardrails for utls-py.
//!
//! As of `boring-sys = "5"` (BoringSSL snapshot Sept 2025+), every
//! fingerprint knob utls needs is upstream:
//!
//! * `SSL_set_permute_extensions` (extension order permutation, Chrome 110+)
//! * `SSL_GROUP_X25519_MLKEM768` (post-quantum hybrid key share, Chrome 124+)
//! * `SSL_add_application_settings` (ALPS)
//! * `SSL_set_enable_ech_grease` / `SSL_set1_ech_config_list` (ECH)
//! * `SSL_CTX_set_grease_enabled`, `SSL_CTX_add_cert_compression_alg`,
//!   `SSL_enable_ocsp_stapling`, `SSL_enable_signed_cert_timestamps`
//!
//! No vendored BoringSSL or patch series is required. This script is kept
//! as a stub so that future build-time invariants have a place to live.

fn main() {
    // No-op. boring-sys 5.x bundles its own BoringSSL with all the APIs
    // we need; we link against it via the standard cargo dependency.
}
