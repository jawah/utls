//! ClientHello capture parser.
//!
//! Given a raw TLS record (handshake type = 1, ClientHello), reconstruct a
//! [`Fingerprint`] that, when re-applied, produces a structurally-equivalent
//! ClientHello.
//!
//! ## Scope
//!
//! * Accepts a single, complete ClientHello record (TLS 1.0-1.3 wrapper).
//! * Does *not* support fragmented ClientHellos (rare in practice).
//! * Does *not* attempt to reconstruct things that can't survive a round-trip,
//!   e.g. the exact random bytes, the session ID, or the actual key share
//!   public values. We reconstruct *shape*: cipher order, extension order,
//!   group order, sigalg order, ALPN order, ALPS, GREASE, padding length.
//!
//! ## Robustness
//!
//! All slicing is bounds-checked. Malformed input returns
//! [`Error::Usage`] with a clear message; it never panics.

use super::spec::{CertCompressAlg, EchPolicy, Fingerprint, GREASE_EXTENSION};
use crate::error::{Error, Result};

const TLS_HANDSHAKE_RECORD: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// Parse a raw `ClientHello` (TLS record) into a [`Fingerprint`].
pub fn parse_client_hello(raw: &[u8]) -> Result<Fingerprint> {
    let mut r = Reader::new(raw);

    // TLS record header: type(1) + version(2) + length(2).
    let rec_type = r.u8("record type")?;
    if rec_type != TLS_HANDSHAKE_RECORD {
        return Err(Error::Usage(format!(
            "expected TLS handshake record (0x16), got 0x{:02x}",
            rec_type
        )));
    }
    let _legacy_version = r.u16("record version")?;
    let rec_len = r.u16("record length")? as usize;
    let body = r.take(rec_len, "record body")?;

    let mut r = Reader::new(body);
    // Handshake header: type(1) + length(3).
    let hs_type = r.u8("handshake type")?;
    if hs_type != HANDSHAKE_CLIENT_HELLO {
        return Err(Error::Usage(format!(
            "expected ClientHello (0x01), got 0x{:02x}",
            hs_type
        )));
    }
    let hs_len = r.u24("handshake length")? as usize;
    let body = r.take(hs_len, "handshake body")?;

    let mut r = Reader::new(body);
    let _legacy_version = r.u16("client_version")?;
    let _random = r.take(32, "random")?;
    let sid_len = r.u8("session_id length")? as usize;
    let _session_id = r.take(sid_len, "session_id")?;

    // Cipher suites.
    let cs_len = r.u16("cipher_suites length")? as usize;
    let cs_bytes = r.take(cs_len, "cipher_suites")?;
    if cs_len % 2 != 0 {
        return Err(Error::Usage("cipher_suites length is not even".into()));
    }
    let mut cipher_suites = Vec::with_capacity(cs_len / 2);
    for chunk in cs_bytes.chunks_exact(2) {
        let cs = u16::from_be_bytes([chunk[0], chunk[1]]);
        if is_grease(cs) {
            continue; // strip GREASE values from the captured cipher list
        }
        cipher_suites.push(cs);
    }

    // Legacy compression_methods.
    let cm_len = r.u8("compression_methods length")? as usize;
    let _ = r.take(cm_len, "compression_methods")?;

    // Extensions block (may be absent in legacy hellos; tolerate).
    let mut fp = Fingerprint {
        cipher_suites,
        grease: false,
        ..Default::default()
    };

    if r.remaining() == 0 {
        return Ok(fp);
    }
    let ext_total = r.u16("extensions length")? as usize;
    let ext_bytes = r.take(ext_total, "extensions block")?;

    let mut er = Reader::new(ext_bytes);
    let mut saw_grease_ext = false;
    while er.remaining() > 0 {
        let ext_type = er.u16("extension type")?;
        let ext_len = er.u16("extension length")? as usize;
        let ext_body = er.take(ext_len, "extension body")?;

        if is_grease(ext_type) {
            saw_grease_ext = true;
            fp.extensions_order.push(GREASE_EXTENSION);
            continue;
        }
        fp.extensions_order.push(ext_type);
        parse_extension(ext_type, ext_body, &mut fp)?;
    }
    if saw_grease_ext {
        fp.grease = true;
    }
    Ok(fp)
}

fn parse_extension(ext_type: u16, body: &[u8], fp: &mut Fingerprint) -> Result<()> {
    let mut r = Reader::new(body);
    match ext_type {
        // supported_groups
        10 => {
            let l = r.u16("supported_groups length")? as usize;
            let b = r.take(l, "supported_groups")?;
            for chunk in b.chunks_exact(2) {
                let g = u16::from_be_bytes([chunk[0], chunk[1]]);
                if !is_grease(g) {
                    fp.supported_groups.push(g);
                }
            }
        }
        // signature_algorithms
        13 => {
            let l = r.u16("signature_algorithms length")? as usize;
            let b = r.take(l, "signature_algorithms")?;
            for chunk in b.chunks_exact(2) {
                let s = u16::from_be_bytes([chunk[0], chunk[1]]);
                if !is_grease(s) {
                    fp.signature_algorithms.push(s);
                }
            }
        }
        // application_layer_protocol_negotiation
        16 => {
            let l = r.u16("alpn length")? as usize;
            let mut ar = Reader::new(r.take(l, "alpn list")?);
            while ar.remaining() > 0 {
                let pl = ar.u8("alpn proto length")? as usize;
                let pb = ar.take(pl, "alpn proto")?;
                fp.alpn.push(String::from_utf8_lossy(pb).into_owned());
            }
        }
        // key_share
        51 => {
            let l = r.u16("key_share list length")? as usize;
            let mut kr = Reader::new(r.take(l, "key_share list")?);
            while kr.remaining() > 0 {
                let group = kr.u16("key_share group")?;
                let kl = kr.u16("key_share length")? as usize;
                let _ = kr.take(kl, "key_share key")?;
                if !is_grease(group) {
                    fp.key_shares.push(group);
                }
            }
        }
        // compress_certificate (codepoint 27)
        27 => {
            let l = r.u8("compress_certificate count")? as usize;
            let b = r.take(l, "compress_certificate algs")?;
            for chunk in b.chunks_exact(2) {
                let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                match id {
                    1 => fp.compress_certificate.push(CertCompressAlg::Zlib),
                    2 => fp.compress_certificate.push(CertCompressAlg::Brotli),
                    3 => fp.compress_certificate.push(CertCompressAlg::Zstd),
                    _ => {}
                }
            }
        }
        // application_settings (ALPS, codepoint 17513)
        17513 => {
            let l = r.u16("alps length")? as usize;
            let mut ar = Reader::new(r.take(l, "alps list")?);
            while ar.remaining() > 0 {
                let pl = ar.u8("alps proto length")? as usize;
                let pb = ar.take(pl, "alps proto")?;
                fp.alps.push(String::from_utf8_lossy(pb).into_owned());
            }
        }
        // record_size_limit
        28 => {
            fp.record_size_limit = Some(r.u16("record_size_limit")?);
        }
        // encrypted_client_hello
        65037 => {
            // We can't tell GREASE vs real ECH from outside without parsing
            // the inner structure; mark as GREASE so re-apply produces a
            // similarly-shaped extension. Real ECH config can be set
            // explicitly by the caller.
            fp.ech = EchPolicy::Grease;
        }
        // padding
        21 => {
            fp.padding = Some(body.len());
        }
        _ => {
            // Unknown / not modeled - extension is preserved in
            // `extensions_order` so the shape is reproduced.
        }
    }
    Ok(())
}

#[inline]
fn is_grease(v: u16) -> bool {
    // GREASE values per RFC 8701 - both bytes equal and high nibble == 0xA.
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

/// Tiny bounds-checked byte reader.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize, label: &str) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Usage(format!(
                "truncated ClientHello: need {n} more bytes for {label}, have {}",
                self.remaining()
            )));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self, label: &str) -> Result<u8> {
        Ok(self.take(1, label)?[0])
    }
    fn u16(&mut self, label: &str) -> Result<u16> {
        let b = self.take(2, label)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self, label: &str) -> Result<u32> {
        let b = self.take(3, label)?;
        Ok(((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x0A0A));
        assert!(is_grease(0xFAFA));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0xFFFE));
    }

    #[test]
    fn rejects_non_handshake_record() {
        let raw = [0x17u8, 0x03, 0x03, 0x00, 0x00];
        let err = parse_client_hello(&raw).unwrap_err();
        matches!(err, Error::Usage(_));
    }

    #[test]
    fn truncation_does_not_panic() {
        let raw = [0x16u8, 0x03, 0x01]; // shorter than record header
        assert!(parse_client_hello(&raw).is_err());
    }
}
