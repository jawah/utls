//! JA3 fingerprint hash.
//!
//! JA3 spec: <https://github.com/salesforce/ja3>. The string form is:
//!
//! ```text
//! SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
//! ```
//!
//! Each comma-separated section is a `-`-joined list of decimal codepoints.
//! GREASE values (`0x?A?A`) are stripped per the original spec. We pin the
//! "SSLVersion" field to the *legacy version* (always 771 = 0x0303 = TLS 1.2)
//! because that's what real browsers always send in the ClientHello header
//! since TLS 1.3 moved the real version to the `supported_versions` extension.
//!
//! The output is the **MD5 hex digest** of the string form.

use crate::fingerprint::spec::{Fingerprint, GREASE_EXTENSION};

/// Render the JA3 string form for the given fingerprint.
pub fn ja3_string(fp: &Fingerprint) -> String {
    fn join(values: impl IntoIterator<Item = u16>) -> String {
        values
            .into_iter()
            .filter(|v| !is_grease(*v) && *v != GREASE_EXTENSION)
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-")
    }
    let version = 771u16; // 0x0303, pinned per spec interpretation note above.
    let ciphers = join(fp.cipher_suites.iter().copied());
    let exts = join(fp.extensions_order.iter().copied());
    let curves = join(fp.supported_groups.iter().copied());
    // EC point formats: browsers always send "0" (uncompressed) when this
    // extension is present. We don't model it explicitly in Fingerprint;
    // emit "0" if the extension was present in `extensions_order`, else "".
    let ec_point_formats = if fp.extensions_order.contains(&11) {
        "0".to_string()
    } else {
        String::new()
    };

    format!("{version},{ciphers},{exts},{curves},{ec_point_formats}")
}

/// MD5 hex digest of [`ja3_string`].
pub fn ja3_hash(fp: &Fingerprint) -> String {
    let s = ja3_string(fp);
    md5_hex(s.as_bytes())
}

#[inline]
fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

//
// MD5 is broken for collision resistance but JA3 uses it only as a stable
// 128-bit short identifier; no security claim. We implement it inline rather
// than depend on the `md-5` crate to keep the dep graph tight.

fn md5_hex(data: &[u8]) -> String {
    let d = md5_digest(data);
    let mut s = String::with_capacity(32);
    for b in &d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn md5_digest(data: &[u8]) -> [u8; 16] {
    // Reference implementation following RFC 1321.
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Padding: 1 bit, then zeros to length ≡ 448 (mod 512), then 64-bit length.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in chunk.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(m[g])
                    .rotate_left(S[i]),
            );
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_smoke() {
        // RFC 1321 test vectors.
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(b"The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6",
        );
    }
}
