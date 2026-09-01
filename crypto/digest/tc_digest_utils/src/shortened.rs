//! Output-truncating digest wrapper, ported from Bouncy Castle's `ShortenedDigest`.
//!
//! Wraps any [`TryDigest`] and truncates its output to the first `length` bytes.
//! This is a *plain truncation* — `ShortenedDigest::new(Sha256Digest::new(), 28)` is
//! the first 28 bytes of SHA-256, which is **not** the same as SHA-224 (that uses a
//! different IV). All input methods forward to the base digest unchanged.

use alloc::format;
use alloc::string::String;

use tc_digest::TryDigest;

/// A digest whose output is the first `length` bytes of a base digest.
#[derive(Clone)]
pub struct ShortenedDigest<D> {
    base: D,
    length: usize,
    name: String,
}

impl<D: TryDigest> ShortenedDigest<D> {
    /// Wraps `base`, truncating its output to `length` bytes.
    ///
    /// # Panics
    ///
    /// Panics (mirroring bc's `ArgumentException`) if `length` exceeds the base
    /// digest's output size.
    pub fn new(base: D, length: usize) -> Self {
        assert!(
            length <= base.digest_size(),
            "ShortenedDigest: length exceeds base digest output size"
        );
        let name = format!("{}({})", base.algorithm_name(), length * 8);
        ShortenedDigest { base, length, name }
    }

    /// Returns a reference to the wrapped base digest.
    pub fn base(&self) -> &D {
        &self.base
    }
}

impl<D: TryDigest> TryDigest for ShortenedDigest<D> {
    type Error = D::Error;

    fn algorithm_name(&self) -> &str {
        &self.name
    }

    fn digest_size(&self) -> usize {
        self.length
    }

    fn byte_length(&self) -> usize {
        self.base.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.base.try_update(input)
    }

    fn try_update_byte(&mut self, input: u8) -> Result<(), Self::Error> {
        self.base.try_update_byte(input)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        // 算完整 base 摘要到暫存,再取前 length 位元組。
        let mut tmp = alloc::vec![0u8; self.base.digest_size()];
        self.base.try_do_final(&mut tmp)?;
        output[..self.length].copy_from_slice(&tmp[..self.length]);
        Ok(self.length)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.base.try_reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_digest::Digest;
    use tc_sha::Sha256Digest;

    #[test]
    fn truncates_to_first_n_bytes() {
        // 完整 SHA-256("abc")。
        let mut full = Sha256Digest::new();
        full.update(b"abc");
        let mut full_out = [0u8; 32];
        full.do_final(&mut full_out);

        // 截成前 16 bytes。
        let mut short = ShortenedDigest::new(Sha256Digest::new(), 16);
        assert_eq!(short.digest_size(), 16);
        assert_eq!(short.algorithm_name(), "SHA-256(128)");
        assert_eq!(short.byte_length(), 64); // 轉發 base

        short.update(b"abc");
        let mut short_out = [0u8; 16];
        let n = short.do_final(&mut short_out);
        assert_eq!(n, 16);
        assert_eq!(short_out, full_out[..16]);
    }

    #[test]
    fn forwards_reset_and_chunked_update() {
        let mut short = ShortenedDigest::new(Sha256Digest::new(), 20);
        short.update(b"discard");
        short.reset();
        // 分段餵。
        short.update(b"ab");
        short.update(b"c");
        let mut out = [0u8; 20];
        short.do_final(&mut out);

        let mut full = Sha256Digest::new();
        full.update(b"abc");
        let mut full_out = [0u8; 32];
        full.do_final(&mut full_out);
        assert_eq!(out, full_out[..20]);
    }

    #[test]
    #[should_panic]
    fn rejects_length_over_base_size() {
        // SHA-256 只有 32 bytes,要 33 應 panic。
        let _ = ShortenedDigest::new(Sha256Digest::new(), 33);
    }
}
