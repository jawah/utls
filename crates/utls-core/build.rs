//! Build-time stamping of the BoringSSL provenance string.
//!
//! BoringSSL itself refuses to be versioned (its `OPENSSL_VERSION_TEXT` is a
//! hardcoded `"OpenSSL 1.1.1 (compatible; BoringSSL)"`), so the most useful
//! handle we can offer downstream callers is the `boring-sys` crate version,
//! which pins a specific BoringSSL snapshot at build time. We resolve it
//! from the workspace `Cargo.lock` and bake it into a `BORING_SYS_VERSION`
//! env var that `lib.rs` reads via `env!`.
//!
//! If the lockfile cannot be located (e.g. cdylib built standalone) we fall
//! back to `"unknown"` so the build never breaks.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let version = find_boring_sys_version().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=BORING_SYS_VERSION={version}");
    println!("cargo:rerun-if-changed=build.rs");
    // Re-run when the lockfile changes so a `cargo update` shows up.
    if let Some(lock) = find_cargo_lock() {
        println!("cargo:rerun-if-changed={}", lock.display());
    }
}

fn find_cargo_lock() -> Option<PathBuf> {
    let start = PathBuf::from(env::var("CARGO_MANIFEST_DIR").ok()?);
    for ancestor in start.ancestors() {
        let candidate = ancestor.join("Cargo.lock");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Minimal TOML scrape: find `[[package]]` blocks where `name = "boring-sys"`
/// and read the adjacent `version = "..."`. We deliberately avoid pulling in
/// a TOML parser dependency for a build-script one-liner.
fn find_boring_sys_version() -> Option<String> {
    let text = fs::read_to_string(find_cargo_lock()?).ok()?;
    let mut in_block = false;
    let mut is_target = false;
    let mut version: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if is_target {
                if let Some(v) = version.take() {
                    return Some(v);
                }
            }
            in_block = true;
            is_target = false;
            version = None;
        } else if in_block {
            if let Some(rest) = trimmed.strip_prefix("name = \"") {
                if let Some(name) = rest.strip_suffix('"') {
                    is_target = name == "boring-sys";
                }
            } else if let Some(rest) = trimmed.strip_prefix("version = \"") {
                if let Some(v) = rest.strip_suffix('"') {
                    version = Some(v.to_string());
                }
            }
        }
    }
    if is_target {
        version
    } else {
        None
    }
}
