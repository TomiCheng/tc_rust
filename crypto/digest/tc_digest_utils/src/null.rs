//! Null (pass-through) digest, ported from Bouncy Castle's `NullDigest`.
//!
//! Not a hash at all: it accumulates every input byte and `do_final` returns them
//! verbatim. Used where an API expects a digest but the data is to be passed
//! through unchanged (e.g. signing an already-hashed value). Because it buffers
//! arbitrary-length input, this is the one digest in the crate that needs `alloc`.

use core::convert::Infallible;

use alloc::vec::Vec;

use tc_digest::TryDigest;

/// The null / pass-through digest (bc `NullDigest`).
///
/// [`digest_size`](TryDigest::digest_size) is **not** constant here — it is the
/// number of bytes accumulated so far.
#[derive(Clone, Default)]
pub struct NullDigest {
    /// 累積的輸入位元組;`do_final` 原樣吐回。
    buf: Vec<u8>,
}

impl NullDigest {
    /// Creates a fresh (empty) null digest.
    pub fn new() -> Self {
        Self::default()
    }
}

impl TryDigest for NullDigest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "NULL"
    }

    /// The number of bytes accumulated so far (variable, unlike a real hash).
    fn digest_size(&self) -> usize {
        self.buf.len()
    }

    /// No fixed internal block (bc returns 0 here).
    fn byte_length(&self) -> usize {
        0
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.buf.extend_from_slice(input);
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.buf.len();
        output[..len].copy_from_slice(&self.buf);
        self.buf.clear();
        Ok(len)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.buf.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_digest::Digest;

    #[test]
    fn passes_input_through() {
        let mut d = NullDigest::new();
        d.update(b"hello, ");
        d.update(b"world");
        assert_eq!(d.digest_size(), 12);
        let mut out = [0u8; 12];
        let n = d.do_final(&mut out);
        assert_eq!(n, 12);
        assert_eq!(&out, b"hello, world");
    }

    #[test]
    fn accessors() {
        let d = NullDigest::new();
        assert_eq!(d.algorithm_name(), "NULL");
        assert_eq!(d.digest_size(), 0); // 空 → 0
        assert_eq!(d.byte_length(), 0);
    }

    #[test]
    fn do_final_leaves_reset() {
        let mut d = NullDigest::new();
        d.update(b"abc");
        let mut out = [0u8; 3];
        d.do_final(&mut out);
        // 已清空:再 do_final 寫 0 byte。
        assert_eq!(d.digest_size(), 0);
        let n = d.do_final(&mut []);
        assert_eq!(n, 0);
    }
}
