//! TupleHash — hash of a *tuple* of byte strings (NIST SP 800-185), ported from
//! Bouncy Castle's `TupleHash`.
//!
//! TupleHash unambiguously hashes an ordered tuple of inputs: **each call to
//! [`update`](tc_crypto_core::Digest::update) contributes one tuple element**,
//! length-prefixed with `encode_string`, so `(a, b)` and `(ab,)` produce
//! different digests. It is a cSHAKE with function name `"TupleHash"`; before the
//! first output it absorbs `right_encode(L)` — `L` = requested output length in
//! bits for the fixed digest, or `0` in XOF mode — which makes the fixed-length
//! and arbitrary-length ([`Xof`](tc_crypto_core::Xof)) outputs distinct.

use core::convert::Infallible;

use tc_crypto_core::{TryDigest, TryXof};

use crate::cshake::CShakeDigest;
use crate::xof_utils::{encode_string, right_encode};

const N_TUPLE_HASH: &[u8] = b"TupleHash";

/// A TupleHash128 / TupleHash256 tuple hash (SP 800-185).
#[derive(Clone)]
pub struct TupleHash {
    cshake: CShakeDigest,
    /// 安全參數位元數(128 或 256)。
    bit_length: usize,
    /// 預設輸出位元組數。
    output_length: usize,
    /// 是否尚未擠出(擠出前需吸收 `right_encode`,僅一次)。
    first_output: bool,
}

impl TupleHash {
    /// Creates TupleHash-`bit_length` with customization `s` and the default
    /// output size (`2 × bit_length` bits: 32 bytes for 128, 64 for 256).
    ///
    /// `bit_length` must be 128 or 256.
    pub fn new(bit_length: usize, s: &[u8]) -> Self {
        Self::with_output_size(bit_length, s, bit_length * 2)
    }

    /// Creates TupleHash-`bit_length` with customization `s` and an explicit
    /// output size in **bits** (rounded up to whole bytes).
    ///
    /// # Panics
    ///
    /// Panics (mirroring bc) if `bit_length` is not 128 or 256.
    pub fn with_output_size(bit_length: usize, s: &[u8], output_size_bits: usize) -> Self {
        TupleHash {
            cshake: CShakeDigest::new(bit_length, N_TUPLE_HASH, s),
            bit_length,
            output_length: output_size_bits.div_ceil(8),
            first_output: true,
        }
    }

    /// 擠出前收尾:吸收 `right_encode(output_bits)`(固定模式為輸出位元、XOF 模式為 0)。
    fn wrap_up(&mut self, output_bytes: usize) {
        let enc = right_encode(output_bytes as u64 * 8);
        let _ = self.cshake.try_update(&enc);
        self.first_output = false;
    }
}

impl TryDigest for TupleHash {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        match self.bit_length {
            128 => "TupleHash128",
            _ => "TupleHash256",
        }
    }

    fn digest_size(&self) -> usize {
        self.output_length
    }

    fn byte_length(&self) -> usize {
        self.cshake.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        // 每次 update = 一個元組元素,以 encode_string 長度前綴後餵入 cSHAKE。
        let enc = encode_string(input);
        self.cshake.try_update(&enc)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.output_length;
        self.try_output_final(&mut output[..len])
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.cshake.try_reset()?;
        self.first_output = true;
        Ok(())
    }
}

impl TryXof for TupleHash {
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        // XOF 模式:right_encode(0),表任意長度輸出。
        if self.first_output {
            self.wrap_up(0);
        }
        self.cshake.try_output(output)
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        // 固定模式:right_encode(輸出位元數)。
        if self.first_output {
            self.wrap_up(output.len());
        }
        self.cshake.try_output(output)?;
        self.try_reset()?;
        Ok(output.len())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use tc_crypto_core::{Digest, Xof};

    fn unhex(s: &str) -> Vec<u8> {
        let d: Vec<char> = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        d.chunks(2)
            .map(|p| (p[0].to_digit(16).unwrap() as u8) << 4 | p[1].to_digit(16).unwrap() as u8)
            .collect()
    }

    fn tuple_final(bits: usize, s: &[u8], elems: &[&[u8]]) -> Vec<u8> {
        let mut t = TupleHash::new(bits, s);
        for e in elems {
            t.update(e);
        }
        let mut out = vec![0u8; t.digest_size()];
        t.do_final(&mut out);
        out
    }

    #[test]
    fn accessors() {
        let t = TupleHash::new(128, b"");
        assert_eq!(t.algorithm_name(), "TupleHash128");
        assert_eq!(t.digest_size(), 32);
        assert_eq!(t.byte_length(), 168);

        let t = TupleHash::new(256, b"");
        assert_eq!(t.algorithm_name(), "TupleHash256");
        assert_eq!(t.digest_size(), 64);
        assert_eq!(t.byte_length(), 136);
    }

    // NIST SP 800-185 TupleHash 官方樣本(KMAC_samples.pdf)。
    #[test]
    fn nist_samples_128() {
        let e1: &[u8] = &unhex("000102");
        let e2: &[u8] = &unhex("101112131415");
        let e3: &[u8] = &unhex("202122232425262728");

        // #1:無自訂化,元組 (e1, e2)。
        assert_eq!(
            tuple_final(128, b"", &[e1, e2]),
            unhex("c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1")
        );
        // #2:自訂化 "My Tuple App",元組 (e1, e2)。
        assert_eq!(
            tuple_final(128, b"My Tuple App", &[e1, e2]),
            unhex("75cdb20ff4db1154e841d758e24160c54bae86eb8c13e7f5f40eb35588e96dfb")
        );
        // #3:自訂化,元組 (e1, e2, e3)。
        assert_eq!(
            tuple_final(128, b"My Tuple App", &[e1, e2, e3]),
            unhex("e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804bb6e84")
        );
    }

    #[test]
    fn nist_samples_256() {
        let e1: &[u8] = &unhex("000102");
        let e2: &[u8] = &unhex("101112131415");
        let e3: &[u8] = &unhex("202122232425262728");

        assert_eq!(
            tuple_final(256, b"", &[e1, e2]),
            unhex(
                "cfb7058caca5e668f81a12a20a2195ce97a925f1dba3e7449a56f82201ec6073\
                 11ac2696b1ab5ea2352df1423bde7bd4bb78c9aed1a853c78672f9eb23bbe194"
            )
        );
        assert_eq!(
            tuple_final(256, b"My Tuple App", &[e1, e2]),
            unhex(
                "147c2191d5ed7efd98dbd96d7ab5a11692576f5fe2a5065f3e33de6bba9f3aa1\
                 c4e9a068a289c61c95aab30aee1e410b0b607de3620e24a4e3bf9852a1d4367e"
            )
        );
        assert_eq!(
            tuple_final(256, b"My Tuple App", &[e1, e2, e3]),
            unhex(
                "45000be63f9b6bfd89f54717670f69a9bc763591a4f05c50d68891a744bcc6e7\
                 d6d5b5e82c018da999ed35b0bb49c9678e526abd8e85c13ed254021db9e790ce"
            )
        );
    }

    // XOF 模式(right_encode(0))與固定模式(right_encode(L))結果不同。
    #[test]
    fn xof_mode_differs_from_fixed() {
        let e1: &[u8] = &unhex("000102");
        let e2: &[u8] = &unhex("101112131415");
        let e3: &[u8] = &unhex("202122232425262728");

        // TupleHash128 XOF。
        let mut t = TupleHash::new(128, b"My Tuple App");
        t.update(e1);
        t.update(e2);
        t.update(e3);
        let mut o = [0u8; 32];
        t.output(&mut o);
        assert_ne!(
            o.to_vec(),
            unhex("e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804bb6e84")
        );
        assert_eq!(
            o.to_vec(),
            unhex("900fe16cad098d28e74d632ed852f99daab7f7df4d99e775657885b4bf76d6f8")
        );

        // TupleHash256 XOF。
        let mut t = TupleHash::new(256, b"My Tuple App");
        t.update(e1);
        t.update(e2);
        t.update(e3);
        let mut o = [0u8; 64];
        t.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex(
                "0c59b11464f2336c34663ed51b2b950bec743610856f36c28d1d088d8a244628\
                 4dd09830a6a178dc752376199fae935d86cfdee5913d4922dfd369b66a53c897"
            )
        );
    }

    // do_final 後應重置:重算同一元組回到同一結果。
    #[test]
    fn do_final_resets() {
        let e1: &[u8] = &unhex("000102");
        let e2: &[u8] = &unhex("101112131415");
        let first = tuple_final(128, b"My Tuple App", &[e1, e2]);
        let second = tuple_final(128, b"My Tuple App", &[e1, e2]);
        assert_eq!(first, second);
    }

    // 元組邊界有意義:(a,b) ≠ (ab,)。
    #[test]
    fn tuple_boundaries_matter() {
        let ab = tuple_final(128, b"", &[b"ab"]);
        let a_b = tuple_final(128, b"", &[b"a", b"b"]);
        assert_ne!(ab, a_b);
    }
}
