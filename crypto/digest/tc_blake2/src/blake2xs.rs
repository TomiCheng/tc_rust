//! BLAKE2xs eXtendable-output function, ported from Bouncy Castle's
//! `Blake2xsDigest`.
//!
//! BLAKE2xs turns BLAKE2s into a XOF (see <https://blake2.net/blake2x.pdf>): it
//! hashes the message once into a 32-byte root `h0`, then produces output in
//! 32-byte blocks, each a fresh BLAKE2s over `h0` with a tree/XOF parameter block
//! (the XOF length in the node-offset high bits, an incrementing block index in the
//! low bits, `inner_length = 32`, `fanout = depth = 0`). Output length 1..=2^16-2,
//! or unknown (`UNKNOWN_DIGEST_LENGTH`) up to 2^32 blocks.

use core::convert::Infallible;

use tc_digest::{Digest, TryDigest, TryXof};

use crate::blake2s::Blake2sDigest;

/// Magic value selecting unknown output length (max 2^32 × 32 bytes).
pub const UNKNOWN_DIGEST_LENGTH: usize = 65535;

const INNER: usize = 32;
const MAX_BLOCKS: u64 = 1 << 32;

/// The BLAKE2xs XOF.
#[derive(Clone)]
pub struct Blake2xsDigest {
    /// 期望輸出位元組數(可為 `UNKNOWN_DIGEST_LENGTH`)。
    digest_length: usize,
    /// 根雜湊(接收 update)。
    hash: Blake2sDigest,
    /// 根摘要 h0,首次擠出時算出。
    h0: Option<[u8; INNER]>,
    /// 當前 32-byte 輸出區塊。
    buf: [u8; INNER],
    /// buf 已消耗位元組(INNER = 需算下一區塊)。
    buf_pos: usize,
    /// 已輸出總位元組數。
    digest_pos: usize,
    /// 每區塊 +1 的 node offset(高位 XOF 長度、低位區塊索引)。
    node_offset: u64,
    /// 區塊計數(未知長度時偵測 2^32 上限)。
    block_pos: u64,
}

impl Default for Blake2xsDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2xsDigest {
    /// Creates a BLAKE2xs XOF with unknown output length.
    pub fn new() -> Self {
        Self::with_parameters(UNKNOWN_DIGEST_LENGTH, None, None, None)
    }

    /// Creates a BLAKE2xs XOF with a fixed output length in bytes (1..=2^16-2).
    pub fn with_digest_size(digest_bytes: usize) -> Self {
        Self::with_parameters(digest_bytes, None, None, None)
    }

    /// Creates a BLAKE2xs XOF with a key, output length, salt and personalization.
    ///
    /// `digest_bytes` is 1..=2^16-1 (`UNKNOWN_DIGEST_LENGTH` selects unknown
    /// length); `key` ≤ 32 bytes; salt/personalization 8 bytes when present.
    ///
    /// # Panics
    ///
    /// Panics if `digest_bytes` is 0 or greater than `UNKNOWN_DIGEST_LENGTH`.
    pub fn with_parameters(
        digest_bytes: usize,
        key: Option<&[u8]>,
        salt: Option<&[u8]>,
        personalization: Option<&[u8]>,
    ) -> Self {
        assert!(
            (1..=UNKNOWN_DIGEST_LENGTH).contains(&digest_bytes),
            "BLAKE2xs digest length must be between 1 and 2^16-1"
        );
        let node_offset = (digest_bytes as u64) << 32;
        let hash = Blake2sDigest::xof_root(INNER, key, salt, personalization, node_offset);
        Blake2xsDigest {
            digest_length: digest_bytes,
            hash,
            h0: None,
            buf: [0; INNER],
            buf_pos: INNER,
            digest_pos: 0,
            node_offset,
            block_pos: 0,
        }
    }

    /// 下一區塊要取的長度(未知長度恆為 32,否則 min(32, 剩餘))。
    fn step_length(&self) -> usize {
        if self.digest_length == UNKNOWN_DIGEST_LENGTH {
            INNER
        } else {
            INNER.min(self.digest_length - self.digest_pos)
        }
    }
}

impl TryDigest for Blake2xsDigest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "BLAKE2xs"
    }

    fn digest_size(&self) -> usize {
        self.digest_length
    }

    fn byte_length(&self) -> usize {
        self.hash.byte_length()
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.hash.try_update(input)
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let len = self.digest_length;
        self.try_output_final(&mut output[..len])
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.hash.try_reset()?;
        self.h0 = None;
        self.buf_pos = INNER;
        self.digest_pos = 0;
        self.block_pos = 0;
        self.node_offset = (self.digest_length as u64) << 32;
        Ok(())
    }
}

impl TryXof for Blake2xsDigest {
    fn try_output(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        // 首次擠出:算出根摘要 h0。
        if self.h0.is_none() {
            let mut h = [0u8; INNER];
            self.hash.do_final(&mut h);
            self.h0 = Some(h);
        }

        if self.digest_length != UNKNOWN_DIGEST_LENGTH {
            assert!(
                self.digest_pos + output.len() <= self.digest_length,
                "BLAKE2xs: output length exceeds the requested digest length"
            );
        } else {
            assert!(
                self.block_pos * (INNER as u64) < MAX_BLOCKS * (INNER as u64),
                "BLAKE2xs: maximum output is 2^32 blocks of 32 bytes"
            );
        }

        let h0 = self.h0.expect("h0 computed above");
        for out in output.iter_mut() {
            if self.buf_pos >= INNER {
                let step = self.step_length();
                let mut node = Blake2sDigest::xof_node(step, INNER as u8, self.node_offset);
                node.update(&h0);
                node.do_final(&mut self.buf);
                self.buf_pos = 0;
                self.node_offset += 1;
                self.block_pos += 1;
            }
            *out = self.buf[self.buf_pos];
            self.buf_pos += 1;
            self.digest_pos += 1;
        }

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
    use tc_digest::Xof;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn accessors() {
        let d = Blake2xsDigest::with_digest_size(64);
        assert_eq!(d.algorithm_name(), "BLAKE2xs");
        assert_eq!(d.digest_size(), 64);
        assert_eq!(d.byte_length(), 64);
    }

    // 分段擠出應與一次擠出相同(串流連續性)。
    #[test]
    fn streamed_output_matches_single() {
        let mut a = Blake2xsDigest::with_digest_size(100);
        a.update(b"the quick brown fox");
        let mut whole = [0u8; 100];
        a.output(&mut whole);

        let mut b = Blake2xsDigest::with_digest_size(100);
        b.update(b"the quick brown fox");
        let mut streamed = [0u8; 100];
        let (mut off, sizes) = (0usize, [1usize, 31, 32, 33, 3]);
        for s in sizes {
            b.output(&mut streamed[off..off + s]);
            off += s;
        }
        b.output(&mut streamed[off..]);
        assert_eq!(whole, streamed);
    }

    // 不同輸出長度是不同函式:長度 L 的輸出 ≠ 長度 2L 的前 L 個位元組。
    #[test]
    fn output_length_is_part_of_the_function() {
        let mut a = Blake2xsDigest::with_digest_size(32);
        a.update(b"abc");
        let mut oa = [0u8; 32];
        a.output_final(&mut oa);

        let mut b = Blake2xsDigest::with_digest_size(64);
        b.update(b"abc");
        let mut ob = [0u8; 64];
        b.output_final(&mut ob);
        assert_ne!(oa, ob[..32]);
    }

    #[test]
    fn output_final_resets() {
        let mut a = Blake2xsDigest::with_digest_size(40);
        a.update(b"first");
        let mut o1 = vec![0u8; 40];
        a.output_final(&mut o1);
        a.update(b"first");
        let mut o2 = vec![0u8; 40];
        a.output_final(&mut o2);
        assert_eq!(o1, o2);
        let _ = hex(&o1);
    }
}
