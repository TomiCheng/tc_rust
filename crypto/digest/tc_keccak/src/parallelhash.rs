//! ParallelHash — parallelizable hash of long strings (NIST SP 800-185), ported
//! from Bouncy Castle's `ParallelHash`.
//!
//! ParallelHash splits the message into fixed `B`-byte blocks, hashes each block
//! independently with a plain SHAKE `compressor` into a `2·bit_length`-bit chaining
//! value, and feeds those chaining values into an outer cSHAKE (`N = "ParallelHash"`)
//! prefixed with `left_encode(B)`. Before the first output it absorbs
//! `right_encode(block_count) || right_encode(L)` — `L` = output length in bits for
//! the fixed digest, or `0` in XOF mode ([`tc_digest::Xof`]) — so the two
//! output modes stay distinct.
//!
//! The per-block independence is what lets a caller parallelize the compressor
//! stage; this port keeps the (sequential) bit-exact behaviour of bc.

use alloc::vec;
use alloc::vec::Vec;
use core::convert::Infallible;

use tc_digest::{Digest, TryDigest, TryXof, Xof};

use crate::cshake::CShakeDigest;
use crate::xof_utils::{left_encode, right_encode};

const N_PARALLEL_HASH: &[u8] = b"ParallelHash";

/// A ParallelHash128 / ParallelHash256 hash (SP 800-185).
#[derive(Clone)]
pub struct ParallelHash {
    /// 外層彙整雜湊(N = "ParallelHash",客製化 S)。
    cshake: CShakeDigest,
    /// 逐 block 壓縮器(純 SHAKE,無客製化)。
    compressor: CShakeDigest,
    /// 安全參數位元數(128 或 256)。
    bit_length: usize,
    /// 預設輸出位元組數。
    output_length: usize,
    /// 區塊大小 B(位元組)。
    block_size: usize,
    /// 壓縮鏈值長度 = `2·bit_length/8`(32 或 64)。
    compressor_len: usize,
    /// B 位元組累積緩衝。
    buffer: Vec<u8>,
    /// 緩衝已填位元組。
    buf_off: usize,
    /// 已壓縮區塊數。
    n_count: u64,
    /// 是否尚未擠出(擠出前需收尾,僅一次)。
    first_output: bool,
}

impl ParallelHash {
    /// Creates ParallelHash-`bit_length` with customization `s`, block size `b`
    /// (bytes) and the default output size (`2 × bit_length` bits).
    ///
    /// `bit_length` must be 128 or 256; `b` must be greater than 0.
    pub fn new(bit_length: usize, s: &[u8], b: usize) -> Self {
        Self::with_output_size(bit_length, s, b, bit_length * 2)
    }

    /// Creates ParallelHash-`bit_length` with an explicit output size in bits.
    ///
    /// # Panics
    ///
    /// Panics (mirroring bc) if `bit_length` is not 128/256 or `b` is 0.
    pub fn with_output_size(
        bit_length: usize,
        s: &[u8],
        b: usize,
        output_size_bits: usize,
    ) -> Self {
        assert!(b > 0, "ParallelHash: block size must be greater than 0");
        let mut h = ParallelHash {
            cshake: CShakeDigest::new(bit_length, N_PARALLEL_HASH, s),
            compressor: CShakeDigest::new(bit_length, b"", b""),
            bit_length,
            output_length: output_size_bits.div_ceil(8),
            block_size: b,
            compressor_len: bit_length * 2 / 8,
            buffer: vec![0u8; b],
            buf_off: 0,
            n_count: 0,
            first_output: true,
        };
        h.init();
        h
    }

    /// Reset 的共同初始化:重置 cSHAKE 並吸收 `left_encode(B)` 標頭。
    fn init(&mut self) {
        self.cshake.reset();
        self.buffer.iter_mut().for_each(|b| *b = 0);
        let hdr = left_encode(self.block_size as u64);
        self.cshake.update(&hdr);
        self.n_count = 0;
        self.buf_off = 0;
        self.first_output = true;
    }

    /// 壓縮一個 block:純 SHAKE(compressor)→ 鏈值 → 餵入外層 cSHAKE。
    fn compress_slice(&mut self, block: &[u8]) {
        self.compressor.update(block);
        let clen = self.compressor_len;
        let mut cb = [0u8; 64];
        self.compressor.output_final(&mut cb[..clen]);
        self.cshake.update(&cb[..clen]);
        self.n_count += 1;
    }

    /// 壓縮緩衝內的殘留 block(`mem::take` 暫借出以避開整體 `&mut self` 借用衝突)。
    fn compress_pending(&mut self) {
        let buf = core::mem::take(&mut self.buffer);
        self.compress_slice(&buf[..self.buf_off]);
        self.buffer = buf;
        self.buf_off = 0;
    }

    /// 擠出前收尾:必要時壓縮殘留,吸收 `right_encode(nCount) || right_encode(L_bits)`。
    fn wrap_up(&mut self, output_bits: u64) {
        if self.buf_off != 0 {
            self.compress_pending();
        }
        let n_enc = right_encode(self.n_count);
        let out_enc = right_encode(output_bits);
        self.cshake.update(&n_enc);
        self.cshake.update(&out_enc);
        self.first_output = false;
    }
}

impl TryDigest for ParallelHash {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        match self.bit_length {
            128 => "ParallelHash128",
            _ => "ParallelHash256",
        }
    }

    fn digest_size(&self) -> usize {
        self.output_length
    }

    fn byte_length(&self) -> usize {
        self.cshake.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let len = input.len();
        let mut i = 0;

        // 先補滿當前部分 block。
        if self.buf_off != 0 {
            while i < len && self.buf_off != self.block_size {
                self.buffer[self.buf_off] = input[i];
                self.buf_off += 1;
                i += 1;
            }
            if self.buf_off == self.block_size {
                self.compress_pending();
            }
        }

        // 整段的完整 block 直接自輸入壓縮(免複製、可平行化的核心)。
        while len - i >= self.block_size {
            self.compress_slice(&input[i..i + self.block_size]);
            i += self.block_size;
        }

        // 殘餘進緩衝。
        while i < len {
            self.buffer[self.buf_off] = input[i];
            self.buf_off += 1;
            i += 1;
            if self.buf_off == self.block_size {
                self.compress_pending();
            }
        }
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.output_length;
        self.try_output_final(&mut output[..len])
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.init();
        Ok(())
    }
}

impl TryXof for ParallelHash {
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        // XOF 模式:right_encode(0)。
        if self.first_output {
            self.wrap_up(0);
        }
        self.cshake.try_output(output)
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        // 固定模式:right_encode(輸出位元數 = 設定的摘要長度)。
        if self.first_output {
            self.wrap_up(self.output_length as u64 * 8);
        }
        self.cshake.try_output(output)?;
        self.try_reset()?;
        Ok(output.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn unhex(s: &str) -> Vec<u8> {
        let d: Vec<char> = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        d.chunks(2)
            .map(|p| (p[0].to_digit(16).unwrap() as u8) << 4 | p[1].to_digit(16).unwrap() as u8)
            .collect()
    }

    // 官方樣本用的兩段訊息。
    fn data24() -> Vec<u8> {
        unhex("000102030405060710111213141516172021222324252627")
    }
    fn data72() -> Vec<u8> {
        unhex(
            "000102030405060708090a0b101112131415161718191a1b\
             202122232425262728292a2b303132333435363738393a3b\
             404142434445464748494a4b505152535455565758595a5b",
        )
    }

    fn ph_final(bits: usize, s: &[u8], b: usize, msg: &[u8]) -> Vec<u8> {
        let mut h = ParallelHash::new(bits, s, b);
        h.update(msg);
        let mut out = vec![0u8; h.digest_size()];
        h.do_final(&mut out);
        out
    }

    #[test]
    fn accessors() {
        let h = ParallelHash::new(128, b"", 8);
        assert_eq!(h.algorithm_name(), "ParallelHash128");
        assert_eq!(h.digest_size(), 32);
        assert_eq!(h.byte_length(), 168);

        let h = ParallelHash::new(256, b"", 8);
        assert_eq!(h.algorithm_name(), "ParallelHash256");
        assert_eq!(h.digest_size(), 64);
        assert_eq!(h.byte_length(), 136);
    }

    // NIST SP 800-185 ParallelHash 官方樣本(固定摘要模式)。
    #[test]
    fn nist_samples_fixed() {
        assert_eq!(
            ph_final(128, b"", 8, &data24()),
            unhex("ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5")
        );
        assert_eq!(
            ph_final(128, b"Parallel Data", 8, &data24()),
            unhex("fc484dcb3f84dceedc353438151bee58157d6efed0445a81f165e495795b7206")
        );
        assert_eq!(
            ph_final(128, b"Parallel Data", 12, &data72()),
            unhex("f7fd5312896c6685c828af7e2adb97e393e7f8d54e3c2ea4b95e5aca3796e8fc")
        );
        assert_eq!(
            ph_final(256, b"", 8, &data24()),
            unhex(
                "bc1ef124da34495e948ead207dd9842235da432d2bbc54b4c110e64c45110553\
                 1b7f2a3e0ce055c02805e7c2de1fb746af97a1dd01f43b824e31b87612410429"
            )
        );
        assert_eq!(
            ph_final(256, b"Parallel Data", 8, &data24()),
            unhex(
                "cdf15289b54f6212b4bc270528b49526006dd9b54e2b6add1ef6900dda3963bb\
                 33a72491f236969ca8afaea29c682d47a393c065b38e29fae651a2091c833110"
            )
        );
        assert_eq!(
            ph_final(256, b"Parallel Data", 12, &data72()),
            unhex(
                "69d0fcb764ea055dd09334bc6021cb7e4b61348dff375da262671cdec3effa8d\
                 1b4568a6cce16b1cad946ddde27f6ce2b8dee4cd1b24851ebf00eb90d43813e9"
            )
        );
    }

    // XOF 模式(right_encode(0))與固定模式結果不同。
    #[test]
    fn xof_mode() {
        let mut h = ParallelHash::new(128, b"Parallel Data", 12);
        h.update(&data72());
        let mut o = [0u8; 32];
        h.output(&mut o);
        assert_ne!(
            o.to_vec(),
            unhex("f7fd5312896c6685c828af7e2adb97e393e7f8d54e3c2ea4b95e5aca3796e8fc")
        );
        assert_eq!(
            o.to_vec(),
            unhex("0127ad9772ab904691987fcc4a24888f341fa0db2145e872d4efd255376602f0")
        );

        let mut h = ParallelHash::new(256, b"Parallel Data", 12);
        h.update(&data72());
        let mut o = [0u8; 64];
        h.output(&mut o);
        assert_eq!(
            o.to_vec(),
            unhex(
                "6b3e790b330c889a204c2fbc728d809f19367328d852f4002dc829f73afd6bce\
                 fb7fe5b607b13a801c0be5c1170bdb794e339458fdb0e62a6af3d42558970249"
            )
        );
    }

    // 空訊息 + 大 B(62)+ 特殊客製化字串(bc ImplTestEmpty)。
    #[test]
    fn empty_message_large_block() {
        let s = b"Ny0LL2tUmt<+kuN5:Z7pZ_7]R; l/i:%pWbo4}";
        let mut h = ParallelHash::new(256, s, 62);
        h.update(b"");
        let mut o = [0u8; 2];
        h.output(&mut o);
        assert_eq!(o.to_vec(), unhex("13c4"));
    }

    // 分段輸入(跨 block 邊界)應與一次輸入相同。
    #[test]
    fn chunked_matches_whole() {
        let msg = data72();
        let whole = ph_final(128, b"Parallel Data", 12, &msg);

        let mut h = ParallelHash::new(128, b"Parallel Data", 12);
        for chunk in [
            &msg[..5],
            &msg[5..12],
            &msg[12..13],
            &msg[13..48],
            &msg[48..],
        ] {
            h.update(chunk);
        }
        let mut out = vec![0u8; h.digest_size()];
        h.do_final(&mut out);
        assert_eq!(out, whole);
    }

    // do_final 後重置:重算同一輸入回到同一結果。
    #[test]
    fn do_final_resets() {
        let a = ph_final(128, b"", 8, &data24());
        let b = ph_final(128, b"", 8, &data24());
        assert_eq!(a, b);
    }
}
