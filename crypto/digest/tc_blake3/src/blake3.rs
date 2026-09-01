//! BLAKE3 hash / XOF, ported from Bouncy Castle's `Blake3Digest`.
//!
//! BLAKE3 is a tree hash: the message is split into 1024-byte chunks, each chunk
//! compressed in 64-byte blocks (a BLAKE2s-like 7-round mix, but with rotate-right
//! and a fixed permutation), and chunk chaining values merged pairwise up a binary
//! tree (the `stack`). The root node is flagged `ROOT`, after which the digest
//! becomes an extendable-output function ([`TryXof`]). Supports the unkeyed,
//! keyed-hash, and derive-key modes.

use alloc::vec::Vec;
use core::convert::Infallible;

use tc_digest::{Digest, TryDigest, TryXof};

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;
const ROUNDS: usize = 7;

// Flags。
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const KEYED_HASH: u32 = 16;
const DERIVE_CONTEXT: u32 = 32;
const DERIVE_KEY: u32 = 64;

// V 狀態的索引。
const COUNT0: usize = 12;
const COUNT1: usize = 13;
const DATALEN: usize = 14;
const FLAGS: usize = 15;

const SIGMA: [u8; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The BLAKE3 hash / extendable-output function.
#[derive(Clone)]
pub struct Blake3Digest {
    /// 64-byte 輸入/輸出緩衝。
    buffer: [u8; BLOCK_LEN],
    /// 金鑰字(unkeyed = IV)。
    k: [u32; 8],
    /// 當前鏈結值。
    chaining: [u32; 8],
    /// 16-word 狀態。
    v: [u32; 16],
    /// 16-word 訊息字。
    m: [u32; 16],
    /// 鏈結值堆疊(二元樹合併)。
    stack: Vec<[u32; 8]>,
    /// 預設輸出位元組數。
    digest_len: usize,
    /// 是否已進入擠出階段。
    outputting: bool,
    /// 目前模式(0 / KEYED_HASH / DERIVE_CONTEXT / DERIVE_KEY)。
    mode: u32,
    /// 擠出時的 flags 與 dataLen。
    output_mode: u32,
    output_data_len: u32,
    /// 區塊計數器。
    counter: u64,
    /// 當前 chunk 已處理位元組數。
    curr_bytes: usize,
    /// 緩衝中下一位元組位置。
    pos: usize,
}

impl Default for Blake3Digest {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3Digest {
    /// Creates an unkeyed BLAKE3 with the default 32-byte digest.
    pub fn new() -> Self {
        Self::with_digest_size(256)
    }

    /// Creates an unkeyed BLAKE3 with a default output size in bits.
    pub fn with_digest_size(digest_bits: usize) -> Self {
        Self::init(digest_bits / 8, 0, IV)
    }

    /// Creates a keyed BLAKE3 (keyed-hash mode) with a 32-byte key.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not exactly 32 bytes.
    pub fn with_key(digest_bits: usize, key: &[u8]) -> Self {
        assert_eq!(key.len(), 32, "BLAKE3 key must be exactly 32 bytes");
        let mut k = [0u32; 8];
        load_words_le(key, &mut k);
        Self::init(digest_bits / 8, KEYED_HASH, k)
    }

    /// Creates a BLAKE3 in derive-key mode from a context string.
    pub fn with_derive_key(digest_bits: usize, context: &[u8]) -> Self {
        // 先以 derive-context 模式雜湊 context,取前 32 bytes 當金鑰。
        let mut ctx = Self::init(32, DERIVE_CONTEXT, IV);
        ctx.update(context);
        let mut key_bytes = [0u8; 32];
        ctx.do_final(&mut key_bytes);
        let mut k = [0u32; 8];
        load_words_le(&key_bytes, &mut k);
        Self::init(digest_bits / 8, DERIVE_KEY, k)
    }

    fn init(digest_len: usize, mode: u32, k: [u32; 8]) -> Self {
        Blake3Digest {
            buffer: [0; BLOCK_LEN],
            k,
            chaining: [0; 8],
            v: [0; 16],
            m: [0; 16],
            stack: Vec::new(),
            digest_len,
            outputting: false,
            mode,
            output_mode: 0,
            output_data_len: 0,
            counter: 0,
            curr_bytes: 0,
            pos: 0,
        }
    }

    // ---- 壓縮 ----

    fn mix_g(&mut self, idx: &[u8; 16], msg_idx: usize, a: usize, b: usize, c: usize, d: usize) {
        let m0 = self.m[idx[msg_idx * 2] as usize];
        let m1 = self.m[idx[msg_idx * 2 + 1] as usize];
        self.v[a] = self.v[a].wrapping_add(self.v[b]).wrapping_add(m0);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(16);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(12);
        self.v[a] = self.v[a].wrapping_add(self.v[b]).wrapping_add(m1);
        self.v[d] = (self.v[d] ^ self.v[a]).rotate_right(8);
        self.v[c] = self.v[c].wrapping_add(self.v[d]);
        self.v[b] = (self.v[b] ^ self.v[c]).rotate_right(7);
    }

    fn perform_round(&mut self, idx: &[u8; 16]) {
        self.mix_g(idx, 0, 0, 4, 8, 12);
        self.mix_g(idx, 1, 1, 5, 9, 13);
        self.mix_g(idx, 2, 2, 6, 10, 14);
        self.mix_g(idx, 3, 3, 7, 11, 15);
        self.mix_g(idx, 4, 0, 5, 10, 15);
        self.mix_g(idx, 5, 1, 6, 11, 12);
        self.mix_g(idx, 6, 2, 7, 8, 13);
        self.mix_g(idx, 7, 3, 4, 9, 14);
    }

    fn compress(&mut self) {
        let mut idx: [u8; 16] = core::array::from_fn(|i| i as u8);
        for _ in 0..ROUNDS - 1 {
            self.perform_round(&idx);
            for b in &mut idx {
                *b = SIGMA[*b as usize];
            }
        }
        self.perform_round(&idx);
        self.adjust_chaining();
    }

    fn adjust_chaining(&mut self) {
        if self.outputting {
            for i in 0..8 {
                self.v[i] ^= self.v[i + 8];
                self.v[i + 8] ^= self.chaining[i];
            }
            for (i, word) in self.v.iter().enumerate() {
                self.buffer[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            self.pos = 0;
        } else {
            for i in 0..8 {
                self.chaining[i] = self.v[i] ^ self.v[i + 8];
            }
        }
    }

    // ---- 區塊 / 樹 ----

    fn init_chunk_block(&mut self, data_len: usize, final_block: bool) {
        let src = if self.curr_bytes == 0 {
            &self.k
        } else {
            &self.chaining
        };
        self.v[..8].copy_from_slice(src);
        self.v[8..12].copy_from_slice(&IV[..4]);
        self.v[COUNT0] = self.counter as u32;
        self.v[COUNT1] = (self.counter >> 32) as u32;
        self.v[DATALEN] = data_len as u32;
        self.v[FLAGS] = self.mode
            + if self.curr_bytes == 0 { CHUNK_START } else { 0 }
            + if final_block { CHUNK_END } else { 0 };

        self.curr_bytes += data_len;
        if self.curr_bytes >= CHUNK_LEN {
            self.counter += 1;
            self.curr_bytes = 0;
            self.v[FLAGS] |= CHUNK_END;
        }

        if final_block && self.stack.is_empty() {
            self.set_root();
        }
    }

    fn init_parent_block(&mut self) {
        self.v[..8].copy_from_slice(&self.k);
        self.v[8..12].copy_from_slice(&IV[..4]);
        self.v[COUNT0] = 0;
        self.v[COUNT1] = 0;
        self.v[DATALEN] = BLOCK_LEN as u32;
        self.v[FLAGS] = self.mode | PARENT;
    }

    fn set_root(&mut self) {
        self.v[FLAGS] |= ROOT;
        self.output_mode = self.v[FLAGS];
        self.output_data_len = self.v[DATALEN];
        self.counter = 0;
        self.outputting = true;
        let (head, _) = self.v.split_at(8);
        self.chaining.copy_from_slice(head);
    }

    fn init_m(&mut self, block: &[u8; BLOCK_LEN]) {
        for i in 0..16 {
            self.m[i] = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
    }

    fn compress_block(&mut self, block: &[u8; BLOCK_LEN]) {
        self.init_chunk_block(BLOCK_LEN, false);
        self.init_m(block);
        self.compress();
        if self.curr_bytes == 0 {
            self.adjust_stack();
        }
    }

    fn adjust_stack(&mut self) {
        let mut count = self.counter;
        while count > 0 {
            if count & 1 == 1 {
                break;
            }
            let left = self.stack.pop().expect("stack not empty when merging");
            self.m[..8].copy_from_slice(&left);
            self.m[8..16].copy_from_slice(&self.chaining);
            self.init_parent_block();
            self.compress();
            count >>= 1;
        }
        self.stack.push(self.chaining);
    }

    fn compress_final_block(&mut self, data_len: usize) {
        self.init_chunk_block(data_len, true);
        let block = self.buffer;
        self.init_m(&block);
        self.compress();
        self.process_stack();
    }

    fn process_stack(&mut self) {
        while let Some(left) = self.stack.pop() {
            self.m[..8].copy_from_slice(&left);
            self.m[8..16].copy_from_slice(&self.chaining);
            self.init_parent_block();
            if self.stack.is_empty() {
                self.set_root();
            }
            self.compress();
        }
    }

    fn next_output_block(&mut self) {
        self.counter += 1;
        self.v[..8].copy_from_slice(&self.chaining);
        self.v[8..12].copy_from_slice(&IV[..4]);
        self.v[COUNT0] = self.counter as u32;
        self.v[COUNT1] = (self.counter >> 32) as u32;
        self.v[DATALEN] = self.output_data_len;
        self.v[FLAGS] = self.output_mode;
        self.compress();
    }

    fn update_bytes(&mut self, mut input: &[u8]) {
        assert!(!self.outputting, "BLAKE3: cannot absorb while outputting");
        if input.is_empty() {
            return;
        }

        if self.pos != 0 {
            let remaining = BLOCK_LEN - self.pos;
            if input.len() <= remaining {
                self.buffer[self.pos..self.pos + input.len()].copy_from_slice(input);
                self.pos += input.len();
                return;
            }
            self.buffer[self.pos..].copy_from_slice(&input[..remaining]);
            let block = self.buffer;
            self.compress_block(&block);
            self.pos = 0;
            self.buffer = [0; BLOCK_LEN];
            input = &input[remaining..];
        }

        // 壓縮除了最後一塊以外的所有整塊(最後塊留到收尾)。
        while input.len() > BLOCK_LEN {
            let block: &[u8; BLOCK_LEN] = input[..BLOCK_LEN].try_into().unwrap();
            self.compress_block(block);
            input = &input[BLOCK_LEN..];
        }

        self.buffer[..input.len()].copy_from_slice(input);
        self.pos = input.len();
    }

    fn output_bytes(&mut self, output: &mut [u8]) {
        if !self.outputting {
            self.compress_final_block(self.pos);
        }
        let mut out_pos = 0;
        let mut left = output.len();

        if self.pos < BLOCK_LEN {
            let n = left.min(BLOCK_LEN - self.pos);
            output[out_pos..out_pos + n].copy_from_slice(&self.buffer[self.pos..self.pos + n]);
            self.pos += n;
            out_pos += n;
            left -= n;
        }

        while left > 0 {
            self.next_output_block();
            let n = left.min(BLOCK_LEN);
            output[out_pos..out_pos + n].copy_from_slice(&self.buffer[..n]);
            self.pos += n;
            out_pos += n;
            left -= n;
        }
    }
}

impl TryDigest for Blake3Digest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "BLAKE3"
    }

    fn digest_size(&self) -> usize {
        self.digest_len
    }

    fn byte_length(&self) -> usize {
        BLOCK_LEN
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.update_bytes(input);
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.digest_len;
        self.try_output_final(&mut output[..len])
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.counter = 0;
        self.curr_bytes = 0;
        self.pos = 0;
        self.outputting = false;
        self.buffer = [0; BLOCK_LEN];
        self.stack.clear();
        Ok(())
    }
}

impl TryXof for Blake3Digest {
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.output_bytes(output);
        Ok(output.len())
    }

    fn try_output_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let written = self.try_output(output)?;
        self.try_reset()?;
        Ok(written)
    }
}

/// 從位元組讀 LE u32 字填入 `words`。
fn load_words_le(bytes: &[u8], words: &mut [u32]) {
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap());
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec, vec::Vec};

    use super::*;
    use tc_digest::Xof;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn blake3_hex(input: &[u8], out_len: usize) -> String {
        let mut d = Blake3Digest::new();
        d.update(input);
        let mut out = vec![0u8; out_len];
        d.output_final(&mut out);
        hex(&out)
    }

    // 官方 BLAKE3 空訊息向量:32-byte 與 64-byte(後者同時驗 XOF 續塊)。
    #[test]
    fn empty_vector_and_xof() {
        assert_eq!(
            blake3_hex(b"", 32),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            blake3_hex(b"", 64),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262\
             e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a"
        );
    }

    #[test]
    fn accessors() {
        let d = Blake3Digest::new();
        assert_eq!(d.algorithm_name(), "BLAKE3");
        assert_eq!(d.digest_size(), 32);
        assert_eq!(d.byte_length(), 64);
    }

    // 多 chunk(3000 bytes > 2×1024)分段餵 vs 一次餵應相同,走到樹堆疊合併。
    #[test]
    fn multi_chunk_chunked_matches_whole() {
        let msg: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
        let whole = blake3_hex(&msg, 32);

        let mut d = Blake3Digest::new();
        for c in msg.chunks(7) {
            d.update(c);
        }
        let mut out = [0u8; 32];
        d.output_final(&mut out);
        assert_eq!(hex(&out), whole);
    }

    #[test]
    fn xof_streamed_matches_single() {
        let mut a = Blake3Digest::new();
        a.update(b"the quick brown fox");
        let mut whole = [0u8; 200];
        a.output(&mut whole);

        let mut b = Blake3Digest::new();
        b.update(b"the quick brown fox");
        let mut streamed = [0u8; 200];
        let (mut off, sizes) = (0usize, [1usize, 63, 64, 65, 7]);
        for s in sizes {
            b.output(&mut streamed[off..off + s]);
            off += s;
        }
        b.output(&mut streamed[off..]);
        assert_eq!(whole, streamed);
    }
}
