//! RIPEMD-160 message digest, ported from Bouncy Castle's `RipeMD160Digest`.
//!
//! Two parallel lines of 5 rounds × 16 steps over `MdBuffer<64>` (little-endian).
//! bc fully unrolls the 160 steps; this uses the equivalent table-driven form
//! (message-order and rotation tables verified against bc's unrolled code).

use core::convert::Infallible;

use tc_crypto_core::TryDigest;

use crate::md_buffer::MdBuffer;
use crate::ripemd_common::{f, RL, RR, SL, SR};

const DIGEST_LENGTH: usize = 20;
const BYTE_LENGTH: usize = 64;

const IV: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

// 左線加法常數(每輪);右線常數。
const KL: [u32; 5] = [0x0000_0000, 0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xa953_fd4e];
const KR: [u32; 5] = [0x50a2_8be6, 0x5c4d_d124, 0x6d70_3ef3, 0x7a6d_76e9, 0x0000_0000];

/// The RIPEMD-160 digest, producing a 20-byte hash.
#[derive(Clone)]
pub struct RipeMD160Digest {
    h: [u32; 5],
    buf: MdBuffer<64>,
}

impl Default for RipeMD160Digest {
    fn default() -> Self {
        RipeMD160Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }
}

impl RipeMD160Digest {
    /// Creates a fresh RIPEMD-160 digest.
    pub fn new() -> Self {
        Self::default()
    }

    fn compress(h: &mut [u32; 5], block: &[u8; 64]) {
        let mut x = [0u32; 16];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let (mut al, mut bl, mut cl, mut dl, mut el) = (h[0], h[1], h[2], h[3], h[4]);
        let (mut ar, mut br, mut cr, mut dr, mut er) = (h[0], h[1], h[2], h[3], h[4]);

        for i in 0..80 {
            let round = i / 16;
            // 左線
            let t = al
                .wrapping_add(f(round, bl, cl, dl))
                .wrapping_add(x[RL[i]])
                .wrapping_add(KL[round])
                .rotate_left(SL[i])
                .wrapping_add(el);
            al = el;
            el = dl;
            dl = cl.rotate_left(10);
            cl = bl;
            bl = t;
            // 右線(函式反序)
            let t = ar
                .wrapping_add(f(4 - round, br, cr, dr))
                .wrapping_add(x[RR[i]])
                .wrapping_add(KR[round])
                .rotate_left(SR[i])
                .wrapping_add(er);
            ar = er;
            er = dr;
            dr = cr.rotate_left(10);
            cr = br;
            br = t;
        }

        // 交叉合併兩線。
        let t = h[1].wrapping_add(cl).wrapping_add(dr);
        h[1] = h[2].wrapping_add(dl).wrapping_add(er);
        h[2] = h[3].wrapping_add(el).wrapping_add(ar);
        h[3] = h[4].wrapping_add(al).wrapping_add(br);
        h[4] = h[0].wrapping_add(bl).wrapping_add(cr);
        h[0] = t;
    }
}

impl TryDigest for RipeMD160Digest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "RIPEMD160"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let Self { h, buf } = self;
        buf.update(input, |block| RipeMD160Digest::compress(h, block));
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        {
            let Self { h, buf } = self;
            // RIPEMD 長度欄位為 little-endian 64-bit。
            let bit_len = buf.byte_count() << 3;
            buf.finish(&bit_len.to_le_bytes(), |block| {
                RipeMD160Digest::compress(h, block)
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
        let mut d = RipeMD160Digest::new();
        d.update(input);
        let mut out = [0u8; 20];
        d.do_final(&mut out);
        let mut s = String::with_capacity(40);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // 官方 RIPEMD-160 測試向量。
    #[test]
    fn known_vectors() {
        assert_eq!(hex(b""), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
        assert_eq!(hex(b"a"), "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
        assert_eq!(hex(b"abc"), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
        assert_eq!(hex(b"message digest"), "5d0689ef49d2fae572b881b123a85ffa21595f36");
        assert_eq!(
            hex(b"abcdefghijklmnopqrstuvwxyz"),
            "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"
        );
    }

    #[test]
    fn accessors() {
        let d = RipeMD160Digest::new();
        assert_eq!(d.algorithm_name(), "RIPEMD160");
        assert_eq!(d.digest_size(), 20);
        assert_eq!(d.byte_length(), 64);
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut a = RipeMD160Digest::new();
        a.update(&msg);
        let mut oa = [0u8; 20];
        a.do_final(&mut oa);

        let mut b = RipeMD160Digest::new();
        b.update(&msg[..64]);
        b.update(&msg[64..]);
        let mut ob = [0u8; 20];
        b.do_final(&mut ob);
        assert_eq!(oa, ob);
    }
}
