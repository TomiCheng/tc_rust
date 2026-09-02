//! SHAKE extendable-output functions (FIPS 202), ported from Bouncy Castle's
//! `ShakeDigest`.
//!
//! SHAKE128 and SHAKE256 are the Keccak sponge run as a XOF: the same
//! [`KeccakDigest`] engine with the `0x1f` domain pad, but instead of a fixed
//! digest length the caller squeezes arbitrarily many bytes via the
//! [`tc_digest::Xof`] trait. Used as a plain [`tc_digest::Digest`], each produces
//! its "default" output — twice the security parameter (SHAKE128 → 32 bytes,
//! SHAKE256 → 64 bytes), matching bc's `GetDigestSize`.

use core::convert::Infallible;

use tc_digest::{TryDigest, TryXof};

use crate::keccak::KeccakDigest;

/// A SHAKE128 / SHAKE256 XOF (FIPS 202).
#[derive(Clone)]
pub struct ShakeDigest {
    sponge: KeccakDigest,
    /// 安全參數位元數(128 或 256),決定名稱與預設輸出長度。
    bit_length: usize,
}

impl Default for ShakeDigest {
    /// Creates SHAKE128, matching Bouncy Castle's default constructor.
    fn default() -> Self {
        Self::new(128)
    }
}

impl ShakeDigest {
    /// Creates SHAKE-`bit_length`.
    ///
    /// `bit_length` must be 128 or 256.
    ///
    /// # Panics
    ///
    /// Panics (mirroring bc's `ArgumentException`) for an unsupported parameter.
    pub fn new(bit_length: usize) -> Self {
        assert!(
            matches!(bit_length, 128 | 256),
            "SHAKE: bit length must be 128 or 256"
        );
        ShakeDigest {
            sponge: KeccakDigest::with_domain(bit_length, 0x1f, "SHAKE"),
            bit_length,
        }
    }
}

impl TryDigest for ShakeDigest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        // 名稱不含連字號(SHAKE128 / SHAKE256),異於基底的 "SHAKE-128"。
        match self.bit_length {
            128 => "SHAKE128",
            _ => "SHAKE256",
        }
    }

    fn digest_size(&self) -> usize {
        // bc:fixedOutputLength >> 2,即安全參數的兩倍位元組(128→32、256→64)。
        self.bit_length / 4
    }

    fn byte_length(&self) -> usize {
        self.sponge.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.sponge.try_update(input)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.digest_size();
        self.try_output_final(&mut output[..len])
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.sponge.try_reset()
    }
}

impl TryXof for ShakeDigest {
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.sponge.xof_output(output);
        Ok(output.len())
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let written = self.try_output(output)?;
        self.try_reset()?;
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec};

    use super::*;
    use tc_digest::{Digest, Xof};

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn accessors() {
        let d = ShakeDigest::new(128);
        assert_eq!(d.algorithm_name(), "SHAKE128");
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 168); // rate = 1344 bit

        let d = ShakeDigest::new(256);
        assert_eq!(d.algorithm_name(), "SHAKE256");
        assert_eq!(d.digest_size(), 64);
        assert_eq!(d.byte_length(), 136); // rate = 1088 bit
    }

    // FIPS 202 SHAKE128("") 前 32 位元組。
    #[test]
    fn shake128_empty_default() {
        let mut d = ShakeDigest::new(128);
        let mut out = [0u8; 32];
        d.do_final(&mut out);
        assert_eq!(
            hex(&out),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
    }

    // FIPS 202 SHAKE256("") 前 64 位元組(預設輸出長度)。
    #[test]
    fn shake256_empty_default() {
        let mut d = ShakeDigest::new(256);
        let mut out = [0u8; 64];
        d.do_final(&mut out);
        assert_eq!(
            hex(&out),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
             d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        );
    }

    // do_final 後應 reset:第二次算空字串仍正確。
    #[test]
    fn do_final_resets() {
        let mut d = ShakeDigest::new(128);
        d.update(b"discarded");
        let mut o = [0u8; 32];
        d.do_final(&mut o);
        d.do_final(&mut o);
        assert_eq!(
            hex(&o),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
    }

    // 分段擠出應等同一次擠出(串流連續性,跨越 rate 邊界)。
    #[test]
    fn streamed_output_matches_single() {
        let mut a = ShakeDigest::new(256);
        a.update(b"the quick brown fox");
        let mut whole = [0u8; 400];
        a.output(&mut whole);

        let mut b = ShakeDigest::new(256);
        b.update(b"the quick brown fox");
        let mut streamed = [0u8; 400];
        let (mut off, sizes) = (0usize, [1usize, 135, 136, 3, 40]);
        for s in sizes {
            b.output(&mut streamed[off..off + s]);
            off += s;
        }
        b.output(&mut streamed[off..]);
        assert_eq!(whole, streamed);
    }

    // 擠出後再吸收應 panic(bc 拋 "attempt to absorb while squeezing")。
    #[test]
    #[should_panic(expected = "attempt to absorb while squeezing")]
    fn absorb_after_squeeze_panics() {
        let mut d = ShakeDigest::new(128);
        let mut o = [0u8; 16];
        d.output(&mut o);
        d.update(b"nope");
    }

    #[test]
    fn output_final_resets() {
        let mut a = ShakeDigest::new(128);
        a.update(b"first");
        let mut o1 = vec![0u8; 40];
        a.output_final(&mut o1);
        a.update(b"first");
        let mut o2 = vec![0u8; 40];
        a.output_final(&mut o2);
        assert_eq!(o1, o2);
    }
}
