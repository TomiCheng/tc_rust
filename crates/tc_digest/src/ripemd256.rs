//! RIPEMD-256 message digest, ported from Bouncy Castle's `RipeMD256Digest`.
//!
//! Two independent RIPEMD-128-style lines (4 registers each) that swap one
//! register between them after each round; the two 4-word states are concatenated
//! (32 bytes) with no cross-combine. Shares tables and `f` with the family via
//! [`ripemd_common`](crate::ripemd_common).

use core::convert::Infallible;
use core::mem::swap;

use tc_crypto_core::TryDigest;

use crate::md_buffer::MdBuffer;
use crate::ripemd_common::{f, RL, RR, SL, SR};

const DIGEST_LENGTH: usize = 32;
const BYTE_LENGTH: usize = 64;

// 左線 IV(H0..3)與右線 IV(H4..7)。
const IV: [u32; 8] = [
    0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476,
    0x7654_3210, 0xFEDC_BA98, 0x89AB_CDEF, 0x0123_4567,
];

const KL: [u32; 4] = [0x0000_0000, 0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc];
const KR: [u32; 4] = [0x50a2_8be6, 0x5c4d_d124, 0x6d70_3ef3, 0x0000_0000];

/// The RIPEMD-256 digest, producing a 32-byte hash.
#[derive(Clone)]
pub struct RipeMD256Digest {
    h: [u32; 8],
    buf: MdBuffer<64>,
}

impl Default for RipeMD256Digest {
    fn default() -> Self {
        RipeMD256Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }
}

impl RipeMD256Digest {
    /// Creates a fresh RIPEMD-256 digest.
    pub fn new() -> Self {
        Self::default()
    }

    fn compress(h: &mut [u32; 8], block: &[u8; 64]) {
        let mut x = [0u32; 16];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let (mut al, mut bl, mut cl, mut dl) = (h[0], h[1], h[2], h[3]);
        let (mut ar, mut br, mut cr, mut dr) = (h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let round = i / 16;
            let t = al
                .wrapping_add(f(round, bl, cl, dl))
                .wrapping_add(x[RL[i]])
                .wrapping_add(KL[round])
                .rotate_left(SL[i]);
            al = dl;
            dl = cl;
            cl = bl;
            bl = t;

            let t = ar
                .wrapping_add(f(3 - round, br, cr, dr))
                .wrapping_add(x[RR[i]])
                .wrapping_add(KR[round])
                .rotate_left(SR[i]);
            ar = dr;
            dr = cr;
            cr = br;
            br = t;

            // 每輪末在兩線間交換一個暫存器(round0→a、1→b、2→c、3→d)。
            if i % 16 == 15 {
                match round {
                    0 => swap(&mut al, &mut ar),
                    1 => swap(&mut bl, &mut br),
                    2 => swap(&mut cl, &mut cr),
                    _ => swap(&mut dl, &mut dr),
                }
            }
        }

        // 兩線各自相加回狀態(無交叉)。
        h[0] = h[0].wrapping_add(al);
        h[1] = h[1].wrapping_add(bl);
        h[2] = h[2].wrapping_add(cl);
        h[3] = h[3].wrapping_add(dl);
        h[4] = h[4].wrapping_add(ar);
        h[5] = h[5].wrapping_add(br);
        h[6] = h[6].wrapping_add(cr);
        h[7] = h[7].wrapping_add(dr);
    }
}

impl TryDigest for RipeMD256Digest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "RIPEMD256"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let Self { h, buf } = self;
        buf.update(input, |block| RipeMD256Digest::compress(h, block));
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        {
            let Self { h, buf } = self;
            let bit_len = buf.byte_count() << 3;
            buf.finish(&bit_len.to_le_bytes(), |block| {
                RipeMD256Digest::compress(h, block)
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
        let mut d = RipeMD256Digest::new();
        d.update(input);
        let mut out = [0u8; 32];
        d.do_final(&mut out);
        let mut s = String::with_capacity(64);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // 官方 RIPEMD-256 測試向量。
    #[test]
    fn known_vectors() {
        assert_eq!(
            hex(b""),
            "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d"
        );
        assert_eq!(
            hex(b"a"),
            "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925"
        );
        assert_eq!(
            hex(b"abc"),
            "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65"
        );
        assert_eq!(
            hex(b"message digest"),
            "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e"
        );
        assert_eq!(
            hex(b"abcdefghijklmnopqrstuvwxyz"),
            "649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133"
        );
    }

    #[test]
    fn accessors() {
        let d = RipeMD256Digest::new();
        assert_eq!(d.algorithm_name(), "RIPEMD256");
        assert_eq!(d.digest_size(), 32);
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut a = RipeMD256Digest::new();
        a.update(&msg);
        let mut oa = [0u8; 32];
        a.do_final(&mut oa);
        let mut b = RipeMD256Digest::new();
        b.update(&msg[..64]);
        b.update(&msg[64..]);
        let mut ob = [0u8; 32];
        b.do_final(&mut ob);
        assert_eq!(oa, ob);
    }
}
