//! RIPEMD-320 message digest, ported from Bouncy Castle's `RipeMD320Digest`.
//!
//! Two RIPEMD-160-style lines (5 registers each) that swap one register between
//! them after each of the first four rounds; the two 5-word states are
//! concatenated (40 bytes), with the `e`/`ee` registers cross-added at the end.

use core::convert::Infallible;
use core::mem::swap;

use tc_crypto_core::TryDigest;

use crate::md_buffer::MdBuffer;
use crate::ripemd_common::{f, RL, RR, SL, SR};

const DIGEST_LENGTH: usize = 40;
const BYTE_LENGTH: usize = 64;

const IV: [u32; 10] = [
    0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0,
    0x7654_3210, 0xFEDC_BA98, 0x89AB_CDEF, 0x0123_4567, 0x3C2D_1E0F,
];

const KL: [u32; 5] = [0x0000_0000, 0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xa953_fd4e];
const KR: [u32; 5] = [0x50a2_8be6, 0x5c4d_d124, 0x6d70_3ef3, 0x7a6d_76e9, 0x0000_0000];

/// The RIPEMD-320 digest, producing a 40-byte hash.
#[derive(Clone)]
pub struct RipeMD320Digest {
    h: [u32; 10],
    buf: MdBuffer<64>,
}

impl Default for RipeMD320Digest {
    fn default() -> Self {
        RipeMD320Digest {
            h: IV,
            buf: MdBuffer::new(),
        }
    }
}

impl RipeMD320Digest {
    /// Creates a fresh RIPEMD-320 digest.
    pub fn new() -> Self {
        Self::default()
    }

    fn compress(h: &mut [u32; 10], block: &[u8; 64]) {
        let mut x = [0u32; 16];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let (mut al, mut bl, mut cl, mut dl, mut el) = (h[0], h[1], h[2], h[3], h[4]);
        let (mut ar, mut br, mut cr, mut dr, mut er) = (h[5], h[6], h[7], h[8], h[9]);

        for i in 0..80 {
            let round = i / 16;
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

            // 前四輪末在兩線間交換 bc 的 a/b/c/d 暫存器(第五輪不換)。因本實作採
            // 值輪替,在輪邊界(16 mod 5 = 1)my-slot 與 bc 暫存器錯位,對映為
            // bc 的 a/b/c/d ↔ my 的 b/d/a/c(推導見模組說明)。
            if i % 16 == 15 && round < 4 {
                match round {
                    0 => swap(&mut bl, &mut br),
                    1 => swap(&mut dl, &mut dr),
                    2 => swap(&mut al, &mut ar),
                    _ => swap(&mut cl, &mut cr),
                }
            }
        }

        // 兩線各自相加;e/ee 交叉。
        h[0] = h[0].wrapping_add(al);
        h[1] = h[1].wrapping_add(bl);
        h[2] = h[2].wrapping_add(cl);
        h[3] = h[3].wrapping_add(dl);
        h[4] = h[4].wrapping_add(er);
        h[5] = h[5].wrapping_add(ar);
        h[6] = h[6].wrapping_add(br);
        h[7] = h[7].wrapping_add(cr);
        h[8] = h[8].wrapping_add(dr);
        h[9] = h[9].wrapping_add(el);
    }
}

impl TryDigest for RipeMD320Digest {
    type Error = Infallible;

    fn algorithm_name(&self) -> &str {
        "RIPEMD320"
    }

    fn digest_size(&self) -> usize {
        DIGEST_LENGTH
    }

    fn byte_length(&self) -> usize {
        BYTE_LENGTH
    }

    fn try_update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let Self { h, buf } = self;
        buf.update(input, |block| RipeMD320Digest::compress(h, block));
        Ok(())
    }

    fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        {
            let Self { h, buf } = self;
            let bit_len = buf.byte_count() << 3;
            buf.finish(&bit_len.to_le_bytes(), |block| {
                RipeMD320Digest::compress(h, block)
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
        let mut d = RipeMD320Digest::new();
        d.update(input);
        let mut out = [0u8; 40];
        d.do_final(&mut out);
        let mut s = String::with_capacity(80);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    // 官方 RIPEMD-320 測試向量。
    #[test]
    fn known_vectors() {
        assert_eq!(
            hex(b""),
            "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8"
        );
        assert_eq!(
            hex(b"a"),
            "ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d"
        );
        assert_eq!(
            hex(b"abc"),
            "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d"
        );
        assert_eq!(
            hex(b"message digest"),
            "3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197"
        );
    }

    #[test]
    fn accessors() {
        let d = RipeMD320Digest::new();
        assert_eq!(d.algorithm_name(), "RIPEMD320");
        assert_eq!(d.digest_size(), 40);
    }

    #[test]
    fn chunked_matches_whole() {
        let msg: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut a = RipeMD320Digest::new();
        a.update(&msg);
        let mut oa = [0u8; 40];
        a.do_final(&mut oa);
        let mut b = RipeMD320Digest::new();
        b.update(&msg[..64]);
        b.update(&msg[64..]);
        let mut ob = [0u8; 40];
        b.do_final(&mut ob);
        assert_eq!(oa, ob);
    }
}
