//! RIPEMD-128 message digest, ported from Bouncy Castle's `RipeMD128Digest`.
//!
//! Two parallel lines of 4 rounds × 16 steps over `MdBuffer<64>` (little-endian),
//! 4 working registers each (no 10-bit cross-rotate — that is a RIPEMD-160
//! feature). Shares the message-order / rotation tables and `f` with the rest of
//! the family via [`ripemd_common`](crate::ripemd_common).

use core::convert::Infallible;

use tc_crypto_core::TryDigest;

use crate::md_buffer::MdBuffer;
use crate::ripemd_common::{f, RL, RR, SL, SR};

const DIGEST_LENGTH: usize = 16;
const BYTE_LENGTH: usize = 64;

const IV: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

const KL: [u32; 4] = [0x0000_0000, 0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc];
const KR: [u32; 4] = [0x50a2_8be6, 0x5c4d_d124, 0x6d70_3ef3, 0x0000_0000];

/// The RIPEMD-128 digest, producing a 16-byte hash.
#[derive(Clone)]
pub struct RipeMD128Digest {
    h: [u32; 4],
    buf: MdBuffer<64>,
}

impl Default for RipeMD128Digest {
    fn default() -> Self {
        RipeMD128Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }
}

impl RipeMD128Digest {
    /// Creates a fresh RIPEMD-128 digest.
    pub fn new() -> Self {
        Self::default()
    }

    fn compress(h: &mut [u32; 4], block: &[u8; 64]) {
        let mut x = [0u32; 16];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let (mut al, mut bl, mut cl, mut dl) = (h[0], h[1], h[2], h[3]);
        let (mut ar, mut br, mut cr, mut dr) = (h[0], h[1], h[2], h[3]);

        for i in 0..64 {
            let round = i / 16;
            // 左線(4-reg MD 式輪替)
            let t = al
                .wrapping_add(f(round, bl, cl, dl))
                .wrapping_add(x[RL[i]])
                .wrapping_add(KL[round])
                .rotate_left(SL[i]);
            al = dl;
            dl = cl;
            cl = bl;
            bl = t;
            // 右線(函式反序:f(3 - round))
            let t = ar
                .wrapping_add(f(3 - round, br, cr, dr))
                .wrapping_add(x[RR[i]])
                .wrapping_add(KR[round])
                .rotate_left(SR[i]);
            ar = dr;
            dr = cr;
            cr = br;
            br = t;
        }

        // 交叉合併。
        let t = h[1].wrapping_add(cl).wrapping_add(dr);
        h[1] = h[2].wrapping_add(dl).wrapping_add(ar);
        h[2] = h[3].wrapping_add(al).wrapping_add(br);
        h[3] = h[0].wrapping_add(bl).wrapping_add(cr);
        h[0] = t;
    }
}

impl TryDigest for RipeMD128Digest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "RIPEMD128"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let Self { h, buf } = self;
        buf.update(input, |block| RipeMD128Digest::compress(h, block));
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        {
            let Self { h, buf } = self;
            let bit_len = buf.byte_count() << 3;
            buf.finish(&bit_len.to_le_bytes(), |block| {
                RipeMD128Digest::compress(h, block)
            });
            for (i, &word) in h.iter().enumerate() {
                output[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
        }
        self.try_reset()?;
        Ok(DIGEST_LENGTH)
    }

    fn try_reset(&mut self) -> Result<(), Self::Error> {
        self.h = IV;
        self.buf.reset();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec::Vec};

    use super::*;
    use tc_crypto_core::Digest;

    fn hex(input: &[u8]) -> String {
        let mut d = RipeMD128Digest::new();
        d.update(input);
        let mut out = [0u8; 16];
        d.do_final(&mut out);
        let mut s = String::with_capacity(32);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // 官方 RIPEMD-128 測試向量。
    #[test]
    fn known_vectors() {
        assert_eq!(hex(b""), "cdf26213a150dc3ecb610f18f6b38b46");
        assert_eq!(hex(b"a"), "86be7afa339d0fc7cfc785e72f578d33");
        assert_eq!(hex(b"abc"), "c14a12199c66e4ba84636b0f69144c77");
        assert_eq!(hex(b"message digest"), "9e327b3d6e523062afc1132d7df9d1b8");
        assert_eq!(
            hex(b"abcdefghijklmnopqrstuvwxyz"),
            "fd2aa607f71dc8f510714922b371834e"
        );
    }

    #[test]
    fn accessors() {
        let d = RipeMD128Digest::new();
        assert_eq!(d.algorithm_name(), "RIPEMD128");
        assert_eq!(d.digest_size(), 16);
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut a = RipeMD128Digest::new();
        a.update(&msg);
        let mut oa = [0u8; 16];
        a.do_final(&mut oa);
        let mut b = RipeMD128Digest::new();
        b.update(&msg[..64]);
        b.update(&msg[64..]);
        let mut ob = [0u8; 16];
        b.do_final(&mut ob);
        assert_eq!(oa, ob);
    }
}
