//! Keccak sponge and the Keccak-f[1600] permutation, ported from Bouncy Castle's
//! `KeccakDigest`.
//!
//! Unlike the Merkle–Damgård digests (which build on [`MdBuffer`](crate::md_buffer)),
//! Keccak is a **sponge**: input is XORed rate-bytes at a time into a 1600-bit state
//! (25 × `u64`) with a permutation between blocks (absorb), then output is read back
//! the same way (squeeze). The permutation is pure XOR/AND/NOT/rotate — no integer
//! addition anywhere.
//!
//! [`KeccakDigest`] here is **raw Keccak** (the NIST-competition version, domain pad
//! `0x01`). SHA-3 and SHAKE are the same sponge with a different domain pad
//! (`0x06` / `0x1f`) and reuse [`keccak_f1600`] and the sponge machinery; SHAKE
//! additionally drives the sponge as a XOF via [`KeccakDigest::xof_output`].

use alloc::format;
use alloc::string::String;
use core::convert::Infallible;

use tc_crypto_core::TryDigest;

/// Keccak-f[1600] 的 24 個輪常數(ι 步用)。
#[rustfmt::skip]
const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// The Keccak-f[1600] permutation over a 25-lane (`u64`) state (bc
/// `KeccakPermutation`). 24 rounds of θ, ρ, π, χ, ι.
pub(crate) fn keccak_f1600(a: &mut [u64; 25]) {
    let (mut a00, mut a01, mut a02, mut a03, mut a04) = (a[0], a[1], a[2], a[3], a[4]);
    let (mut a05, mut a06, mut a07, mut a08, mut a09) = (a[5], a[6], a[7], a[8], a[9]);
    let (mut a10, mut a11, mut a12, mut a13, mut a14) = (a[10], a[11], a[12], a[13], a[14]);
    let (mut a15, mut a16, mut a17, mut a18, mut a19) = (a[15], a[16], a[17], a[18], a[19]);
    let (mut a20, mut a21, mut a22, mut a23, mut a24) = (a[20], a[21], a[22], a[23], a[24]);

    for &rc in RC.iter() {
        // θ:直行校驗 + 回饋。
        let c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
        let c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
        let c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
        let c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
        let c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;

        let d1 = c1.rotate_left(1) ^ c4;
        let d2 = c2.rotate_left(1) ^ c0;
        let d3 = c3.rotate_left(1) ^ c1;
        let d4 = c4.rotate_left(1) ^ c2;
        let d0 = c0.rotate_left(1) ^ c3;

        a00 ^= d1; a05 ^= d1; a10 ^= d1; a15 ^= d1; a20 ^= d1;
        a01 ^= d2; a06 ^= d2; a11 ^= d2; a16 ^= d2; a21 ^= d2;
        a02 ^= d3; a07 ^= d3; a12 ^= d3; a17 ^= d3; a22 ^= d3;
        a03 ^= d4; a08 ^= d4; a13 ^= d4; a18 ^= d4; a23 ^= d4;
        a04 ^= d0; a09 ^= d0; a14 ^= d0; a19 ^= d0; a24 ^= d0;

        // ρ + π:固定量左旋並重排 lane。
        let t = a01.rotate_left(1);
        a01 = a06.rotate_left(44);
        a06 = a09.rotate_left(20);
        a09 = a22.rotate_left(61);
        a22 = a14.rotate_left(39);
        a14 = a20.rotate_left(18);
        a20 = a02.rotate_left(62);
        a02 = a12.rotate_left(43);
        a12 = a13.rotate_left(25);
        a13 = a19.rotate_left(8);
        a19 = a23.rotate_left(56);
        a23 = a15.rotate_left(41);
        a15 = a04.rotate_left(27);
        a04 = a24.rotate_left(14);
        a24 = a21.rotate_left(2);
        a21 = a08.rotate_left(55);
        a08 = a16.rotate_left(45);
        a16 = a05.rotate_left(36);
        a05 = a03.rotate_left(28);
        a03 = a18.rotate_left(21);
        a18 = a17.rotate_left(15);
        a17 = a11.rotate_left(10);
        a11 = a07.rotate_left(6);
        a07 = a10.rotate_left(3);
        a10 = t;

        // χ:每列唯一的非線性步。
        let (b0, b1) = (a00 ^ (!a01 & a02), a01 ^ (!a02 & a03));
        a02 ^= !a03 & a04;
        a03 ^= !a04 & a00;
        a04 ^= !a00 & a01;
        a00 = b0;
        a01 = b1;

        let (b0, b1) = (a05 ^ (!a06 & a07), a06 ^ (!a07 & a08));
        a07 ^= !a08 & a09;
        a08 ^= !a09 & a05;
        a09 ^= !a05 & a06;
        a05 = b0;
        a06 = b1;

        let (b0, b1) = (a10 ^ (!a11 & a12), a11 ^ (!a12 & a13));
        a12 ^= !a13 & a14;
        a13 ^= !a14 & a10;
        a14 ^= !a10 & a11;
        a10 = b0;
        a11 = b1;

        let (b0, b1) = (a15 ^ (!a16 & a17), a16 ^ (!a17 & a18));
        a17 ^= !a18 & a19;
        a18 ^= !a19 & a15;
        a19 ^= !a15 & a16;
        a15 = b0;
        a16 = b1;

        let (b0, b1) = (a20 ^ (!a21 & a22), a21 ^ (!a22 & a23));
        a22 ^= !a23 & a24;
        a23 ^= !a24 & a20;
        a24 ^= !a20 & a21;
        a20 = b0;
        a21 = b1;

        // ι
        a00 ^= rc;
    }

    a[0] = a00; a[1] = a01; a[2] = a02; a[3] = a03; a[4] = a04;
    a[5] = a05; a[6] = a06; a[7] = a07; a[8] = a08; a[9] = a09;
    a[10] = a10; a[11] = a11; a[12] = a12; a[13] = a13; a[14] = a14;
    a[15] = a15; a[16] = a16; a[17] = a17; a[18] = a18; a[19] = a19;
    a[20] = a20; a[21] = a21; a[22] = a22; a[23] = a23; a[24] = a24;
}

/// A Keccak sponge digest with fixed output length.
///
/// The public constructor builds **raw Keccak** (domain pad `0x01`); SHA-3 and
/// SHAKE reuse the same engine via [`with_domain`](KeccakDigest::with_domain).
#[derive(Clone)]
pub struct KeccakDigest {
    /// 1600-bit 狀態(25 lane)。
    state: [u64; 25],
    /// rate(位元組):每次吸收/擠出的區塊大小 = (1600 − 2·輸出bit) / 8。
    rate_bytes: usize,
    /// 當前區塊已吸收/擠出的位元組位置。
    pos: usize,
    /// 固定輸出位元組數。
    out_len: usize,
    /// domain separation pad(raw Keccak = 0x01)。
    domain: u8,
    /// 是否已進入擠出階段(pad 之後不得再吸收)。
    squeezing: bool,
    /// 演算法名稱。
    name: String,
}

impl KeccakDigest {
    /// Creates a raw Keccak digest of the given output bit length (one of 128,
    /// 224, 256, 288, 384, 512).
    ///
    /// # Panics
    ///
    /// Panics (mirroring bc's `ArgumentException`) on an unsupported bit length.
    pub fn new(bit_length: usize) -> Self {
        Self::with_domain(bit_length, 0x01, "Keccak")
    }

    /// Builds a sponge digest with a caller-chosen domain pad and name prefix —
    /// used by SHA-3 (`0x06`) and, once ported, SHAKE (`0x1f`). Not for general use.
    pub(crate) fn with_domain(bit_length: usize, domain: u8, name_prefix: &str) -> Self {
        assert!(
            matches!(bit_length, 128 | 224 | 256 | 288 | 384 | 512),
            "Keccak: bit length must be one of 128, 224, 256, 288, 384, 512"
        );
        let rate = 1600 - (bit_length << 1);
        KeccakDigest {
            state: [0; 25],
            rate_bytes: rate / 8,
            pos: 0,
            out_len: bit_length / 8,
            domain,
            squeezing: false,
            name: format!("{name_prefix}-{bit_length}"),
        }
    }

    /// 把一個位元組 XOR 進狀態(LE lane 內);湊滿 rate 就置換。
    #[inline]
    fn absorb_byte(&mut self, b: u8) {
        self.state[self.pos / 8] ^= (b as u64) << ((self.pos % 8) * 8);
        self.pos += 1;
        if self.pos == self.rate_bytes {
            keccak_f1600(&mut self.state);
            self.pos = 0;
        }
    }

    /// 補 pad10*1(domain 開頭 + 尾端最高位),置換一次並切換到擠出階段。
    fn pad_and_switch(&mut self) {
        // domain pad 位於當前位置;pad10*1 的收尾 1 位在 rate 的最後一位元。
        self.state[self.pos / 8] ^= (self.domain as u64) << ((self.pos % 8) * 8);
        let last = self.rate_bytes - 1;
        self.state[last / 8] ^= 0x80u64 << ((last % 8) * 8);
        keccak_f1600(&mut self.state);
        self.pos = 0;
        self.squeezing = true;
    }

    /// 從狀態連續讀出位元組;每讀滿一個 rate 區塊就再置換一次。
    ///
    /// 擠出位置沿用 `pos`(此階段語意為「當前 rate 區塊已讀位元組」),故可跨多次
    /// 呼叫連續擠出(XOF 用)。
    fn squeeze(&mut self, output: &mut [u8]) {
        for out in output.iter_mut() {
            if self.pos == self.rate_bytes {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            *out = (self.state[self.pos / 8] >> ((self.pos % 8) * 8)) as u8;
            self.pos += 1;
        }
    }

    /// XOF 擠出:首次呼叫先補 pad 切換,之後每次續擠(供 SHAKE 等 XOF 使用)。
    ///
    /// 呼叫後不 reset,可反覆呼叫取任意長度輸出;固定輸出的收尾走
    /// [`TryDigest::try_do_final`]。
    pub(crate) fn xof_output(&mut self, output: &mut [u8]) {
        if !self.squeezing {
            self.pad_and_switch();
        }
        self.squeeze(output);
    }
}

impl TryDigest for KeccakDigest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        &self.name
    }

    fn digest_size(&self) -> usize {
        self.out_len
    }

    fn byte_length(&self) -> usize {
        self.rate_bytes
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        assert!(!self.squeezing, "Keccak: attempt to absorb while squeezing");
        for &b in input {
            self.absorb_byte(b);
        }
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.out_len;
        self.pad_and_switch();
        self.squeeze(&mut output[..len]);
        self.try_reset()?;
        Ok(len)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.state = [0; 25];
        self.pos = 0;
        self.squeezing = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec::Vec};

    use super::*;
    use tc_crypto_core::Digest;

    fn hex(bit_length: usize, input: &[u8]) -> String {
        let mut d = KeccakDigest::new(bit_length);
        d.update(input);
        let mut out = alloc::vec![0u8; bit_length / 8];
        d.do_final(&mut out);
        let mut s = String::with_capacity(bit_length / 4);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // 原始 Keccak(非 SHA-3)已知向量。
    #[test]
    fn keccak256_vectors() {
        assert_eq!(
            hex(256, b""),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex(256, b"abc"),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        assert_eq!(
            hex(256, b"The quick brown fox jumps over the lazy dog"),
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
        );
    }

    #[test]
    fn keccak512_empty() {
        assert_eq!(
            hex(512, b""),
            "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304\
             c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"
        );
    }

    #[test]
    fn accessors_and_reset() {
        let mut d = KeccakDigest::new(256);
        assert_eq!(d.algorithm_name(), "Keccak-256");
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 136); // rate = 1088 bit
        d.update(b"abc");
        let mut o = [0u8; 32];
        d.do_final(&mut o);
        // do_final 後應 reset,再算空字串。
        d.do_final(&mut o);
        let s: String = o.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(s, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..400).map(|i| i as u8).collect();
        let mut a = KeccakDigest::new(256);
        a.update(&msg);
        let mut oa = [0u8; 32];
        a.do_final(&mut oa);
        let mut b = KeccakDigest::new(256);
        b.update(&msg[..100]);
        b.update(&msg[100..136]);
        b.update(&msg[136..]);
        let mut ob = [0u8; 32];
        b.do_final(&mut ob);
        assert_eq!(oa, ob);
    }
}
