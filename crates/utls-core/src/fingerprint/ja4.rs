//! JA4 fingerprint hash.
//!
//! **Pinned to JA4 spec revision `0.18.8`** - see FoxIO-LLC/ja4 tag `0.18.8`.
//! This pin is also encoded in `python/utls/_fingerprint.py::JA4_SPEC_VERSION`
//! and the two are asserted equal in CI. Bumping is a minor-version-bump
//! change with a changelog entry.
//!
//! ## Format (TLS variant)
//!
//! ```text
//! JA4 = q|d|<v>|<c>|<e>|<alpn>_<sha256-hex(ciphers)>[..12]_<sha256-hex(exts+sigalgs)>[..12]
//! ```
//!
//! Sections:
//!
//! 1. **Protocol indicator**: `t` (TCP/TLS) or `q` (QUIC). We always emit `t`.
//! 2. **TLS version**: numeric mapping, e.g. `13` for TLS 1.3.
//! 3. **SNI presence**: `d` if SNI is included, `i` if it is omitted. Since
//!    our Fingerprint doesn't track SNI presence directly, we default to `d`
//!    (every browser sends SNI).
//! 4. **Cipher count**: `cc` two-digit count of (non-GREASE) cipher suites.
//! 5. **Extension count**: `ee` two-digit count of (non-GREASE) extensions.
//! 6. **First ALPN value**: two chars of the first ALPN protocol (e.g. `h2`),
//!    or `00` if no ALPN.
//! 7. **Cipher hash**: first 12 hex chars of sha256 of the sorted, comma-
//!    joined, non-GREASE cipher suites in lower-case hex (e.g. `1301,1302,...`).
//! 8. **Extension+sigalg hash**: first 12 hex chars of sha256 of the sorted
//!    non-GREASE extension codepoints joined by `,`, followed by `_`, followed
//!    by the sigalg codepoints **in original order** joined by `,`.
//!
//! Spec details we deliberately follow:
//! * SNI (codepoint 0) and ALPN (codepoint 16) are excluded from the
//!   extension-hash list, per 0.18.8 §"_b" derivation.
//! * Sigalgs are *not* sorted.

use crate::fingerprint::spec::{Fingerprint, GREASE_EXTENSION};

/// The pinned JA4 spec version. Asserted equal to the Python-side constant
/// `utls._fingerprint.JA4_SPEC_VERSION` by CI.
pub const JA4_SPEC_VERSION: &str = "0.18.8";

/// Render the JA4 fingerprint string for the given fingerprint.
pub fn ja4_string(fp: &Fingerprint) -> String {
    // Section 1: protocol indicator.
    let proto = 't';
    // Section 2: TLS version. We deduce from the supported_versions extension's
    // presence - if it's there we assume TLS 1.3, else TLS 1.2. Real browsers
    // always include it for TLS 1.3.
    let tls_version = if fp.extensions_order.contains(&43) {
        "13"
    } else {
        "12"
    };
    // Section 3: SNI presence. Always `d`; utls' Context refuses to wrap_bio
    // without server_hostname when check_hostname=True.
    let sni = 'd';

    // Strip GREASE for counting.
    let ciphers: Vec<u16> = fp
        .cipher_suites
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let exts: Vec<u16> = fp
        .extensions_order
        .iter()
        .copied()
        .filter(|v| !is_grease(*v) && *v != GREASE_EXTENSION)
        .collect();

    let cc = format!("{:02}", ciphers.len().min(99));
    let ee = format!("{:02}", exts.len().min(99));

    // Section 6: first 2 chars of first ALPN, or "00".
    let alpn = match fp.alpn.first() {
        None => "00".to_string(),
        Some(p) => {
            let bytes = p.as_bytes();
            if bytes.len() >= 2 {
                format!("{}{}", char_at(bytes, 0), char_at(bytes, bytes.len() - 1))
            } else if bytes.len() == 1 {
                format!("{}{}", char_at(bytes, 0), char_at(bytes, 0))
            } else {
                "00".to_string()
            }
        }
    };

    // Section 7: sorted cipher hex hash.
    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let cipher_blob = sorted_ciphers
        .iter()
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");
    let cipher_hash = &sha256_hex(cipher_blob.as_bytes())[..12];

    // Section 8: extension hash, excluding SNI(0) and ALPN(16); sigalgs in
    // original order, separated by `_`.
    let mut hash_exts: Vec<u16> = exts
        .iter()
        .copied()
        .filter(|&e| e != 0 && e != 16)
        .collect();
    hash_exts.sort_unstable();
    let ext_blob = hash_exts
        .iter()
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");
    let sig_blob = fp
        .signature_algorithms
        .iter()
        .filter(|v| !is_grease(**v))
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");
    let blob = format!("{ext_blob}_{sig_blob}");
    let ext_hash = &sha256_hex(blob.as_bytes())[..12];

    format!("{proto}{tls_version}{sni}{cc}{ee}{alpn}_{cipher_hash}_{ext_hash}")
}

/// Alias retained for symmetry with `ja3::ja3_hash`. JA4 is itself a string;
/// the "hash" is the full identifier.
pub fn ja4_hash(fp: &Fingerprint) -> String {
    ja4_string(fp)
}

fn char_at(b: &[u8], i: usize) -> char {
    let c = b[i];
    if c.is_ascii_alphanumeric() {
        c as char
    } else {
        '0'
    }
}

#[inline]
fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

//
// As with MD5 in ja3.rs we inline this to avoid an extra crate dep. Constant-
// time concerns don't apply: this is hashing a public fingerprint string.

fn sha256_hex(data: &[u8]) -> String {
    let d = sha256(data);
    let mut s = String::with_capacity(64);
    for b in &d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, b) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let mj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(mj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, w) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_smoke() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    }

    #[test]
    fn spec_version_is_pinned() {
        assert_eq!(JA4_SPEC_VERSION, "0.18.8");
    }
}
