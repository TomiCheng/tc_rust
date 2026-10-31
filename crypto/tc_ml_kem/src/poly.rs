use crate::cbd::{eta2, eta3};
use crate::ntt::{ZETAS, base_mult, inv_ntt, ntt};
use crate::reduce::{Q, barrett_reduce, cond_sub_q, montgomery_reduce};
use alloc::vec;
use tc_digest::{Digest, Xof};
use tc_keccak::ShakeDigest;
use tc_zeroize::{Zeroize, Zeroizing};

/// BC 的 `Poly`：Z_q[X]/(X^256 + 1) 的元素，256 個係數；drop 時清除。
#[derive(Clone)]
pub(crate) struct Poly {
    pub(crate) coeffs: [i16; 256],
}

impl Drop for Poly {
    /// 清除係數。常數時間。
    fn drop(&mut self) {
        self.coeffs.zeroize();
    }
}

impl Poly {
    /// 零多項式。常數時間。
    pub(crate) fn zero() -> Self {
        Self { coeffs: [0; 256] }
    }

    /// BC 的 `GetNoiseEta2`／`GetNoiseEta3`：PRF(seed, nonce) = SHAKE256(seed ‖ nonce) 的
    /// 64·η 個位元組，取中心二項分布。常數時間：只依 η 與長度。
    pub(crate) fn noise(eta: u8, seed: &[u8], nonce: u8) -> Self {
        let mut xof = ShakeDigest::new(256);
        xof.update(&seed[..32]);
        xof.update(&[nonce]);
        let mut bytes = Zeroizing::new(vec![0u8; 64 * usize::from(eta)]);
        xof.output_final(&mut bytes);
        let mut poly = Self::zero();
        if eta == 2 {
            eta2(&mut poly.coeffs, &bytes);
        } else {
            eta3(&mut poly.coeffs, &bytes);
        }
        poly
    }

    /// BC 的 `PolyNtt`：正向 NTT 再約化。常數時間。
    pub(crate) fn ntt(&mut self) {
        ntt(&mut self.coeffs);
        self.reduce();
    }

    /// BC 的 `PolyInverseNttToMont`。常數時間。
    pub(crate) fn inverse_ntt_to_mont(&mut self) {
        inv_ntt(&mut self.coeffs);
    }

    /// BC 的 `BaseMultMontgomery`：NTT 領域裡的乘積。常數時間。
    pub(crate) fn base_mul(a: &Self, b: &Self) -> Self {
        let mut r = Self::zero();
        for i in 0..64 {
            let zeta = ZETAS[64 + i];
            for (offset, zeta) in [(4 * i, zeta), (4 * i + 2, zeta.wrapping_neg())] {
                let (first, second) = base_mult(
                    (a.coeffs[offset], a.coeffs[offset + 1]),
                    (b.coeffs[offset], b.coeffs[offset + 1]),
                    zeta,
                );
                r.coeffs[offset] = first;
                r.coeffs[offset + 1] = second;
            }
        }
        r
    }

    /// BC 的 `ToMont`：乘上 2^16 mod q 轉成 Montgomery 形式。常數時間。
    pub(crate) fn convert_to_mont(&mut self) {
        const F: i32 = ((1u64 << 32) % Q as u64) as i32;
        for coefficient in &mut self.coeffs {
            *coefficient = montgomery_reduce(i32::from(*coefficient) * F);
        }
    }

    /// BC 的 `Add`：逐項相加，不約化。常數時間。
    pub(crate) fn add(&mut self, other: &Self) {
        for (coefficient, other) in self.coeffs.iter_mut().zip(&other.coeffs) {
            *coefficient = coefficient.wrapping_add(*other);
        }
    }

    /// BC 的 `Subtract`：self = other − self，不約化。常數時間。
    pub(crate) fn subtract_from(&mut self, other: &Self) {
        for (coefficient, other) in self.coeffs.iter_mut().zip(&other.coeffs) {
            *coefficient = other.wrapping_sub(*coefficient);
        }
    }

    /// BC 的 `PolyReduce`：每個係數做 Barrett 約化。常數時間。
    pub(crate) fn reduce(&mut self) {
        for coefficient in &mut self.coeffs {
            *coefficient = barrett_reduce(*coefficient);
        }
    }

    /// BC 的 `CondSubQ`。常數時間。
    pub(crate) fn cond_sub_q(&mut self) {
        for coefficient in &mut self.coeffs {
            *coefficient = cond_sub_q(*coefficient);
        }
    }

    /// BC 的 `CompressPoly128`（d = 4）與 `CompressPoly160`（d = 5）：每個係數壓成 d 位元。
    /// 常數時間：除以 q 以乘法與位移代替。
    pub(crate) fn compress(&mut self, output: &mut [u8]) {
        self.cond_sub_q();
        if output.len() == 128 {
            for (pair, byte) in self.coeffs.chunks_exact(2).zip(output.iter_mut()) {
                let t = |c: i16| (((i32::from(c) + (i32::from(Q) >> 5)) * 315) >> 16) & 0xF;
                *byte = (t(pair[0]) | (t(pair[1]) << 4)) as u8;
            }
        } else {
            for (eight, out) in self.coeffs.chunks_exact(8).zip(output.chunks_exact_mut(5)) {
                let t: [u8; 8] = core::array::from_fn(|j| {
                    ((((i32::from(eight[j]) + (i32::from(Q) >> 6)) * 630) >> 16) & 0x1F) as u8
                });
                out[0] = t[0] | (t[1] << 5);
                out[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
                out[2] = (t[3] >> 1) | (t[4] << 4);
                out[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
                out[4] = (t[6] >> 2) | (t[7] << 3);
            }
        }
    }

    /// BC 的 `DecompressPoly128`／`DecompressPoly160`。常數時間：只有乘法與位移。
    pub(crate) fn decompress(input: &[u8]) -> Self {
        let mut poly = Self::zero();
        let q = i32::from(Q);
        if input.len() == 128 {
            for (pair, byte) in poly.coeffs.chunks_exact_mut(2).zip(input) {
                pair[0] = (((i32::from(byte & 15) * q) + 8) >> 4) as i16;
                pair[1] = (((i32::from(byte >> 4) * q) + 8) >> 4) as i16;
            }
        } else {
            for (eight, c) in poly.coeffs.chunks_exact_mut(8).zip(input.chunks_exact(5)) {
                let t = [
                    c[0],
                    (c[0] >> 5) | (c[1] << 3),
                    c[1] >> 2,
                    (c[1] >> 7) | (c[2] << 1),
                    (c[2] >> 4) | (c[3] << 4),
                    c[3] >> 1,
                    (c[3] >> 6) | (c[4] << 2),
                    c[4] >> 3,
                ];
                for (coefficient, t) in eight.iter_mut().zip(t) {
                    *coefficient = ((i32::from(t & 31) * q + 16) >> 5) as i16;
                }
            }
        }
        poly
    }

    /// BC 的 `FromBytes`：每 3 個位元組解出兩個 12 位元的係數。常數時間。
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        let mut poly = Self::zero();
        for (pair, b) in poly.coeffs.chunks_exact_mut(2).zip(bytes.chunks_exact(3)) {
            let (a0, a1, a2) = (u16::from(b[0]), u16::from(b[1]), u16::from(b[2]));
            pair[0] = ((a0 | (a1 << 8)) & 0xFFF) as i16;
            pair[1] = (((a1 >> 4) | (a2 << 4)) & 0xFFF) as i16;
        }
        poly
    }

    /// BC 的 `ToBytes`：每兩個 12 位元的係數寫成 3 個位元組。常數時間。
    pub(crate) fn write_bytes(&mut self, output: &mut [u8]) {
        self.cond_sub_q();
        for (pair, out) in self.coeffs.chunks_exact(2).zip(output.chunks_exact_mut(3)) {
            let (t0, t1) = (pair[0] as u16, pair[1] as u16);
            out[0] = t0 as u8;
            out[1] = ((t0 >> 8) | (t1 << 4)) as u8;
            out[2] = (t1 >> 4) as u8;
        }
    }

    /// BC 的 `ToMsg`：每個係數接近 q/2 時為 1，接近 0 時為 0，組成 32 個位元組。常數時間：
    /// 以符號位元判斷，不分支。
    pub(crate) fn write_message(&mut self, message: &mut [u8; 32]) {
        const LOWER: i32 = (Q as i32) >> 2;
        const UPPER: i32 = Q as i32 - LOWER;
        self.cond_sub_q();
        for (eight, byte) in self.coeffs.chunks_exact(8).zip(message.iter_mut()) {
            let mut value = 0u32;
            for (j, coefficient) in eight.iter().enumerate() {
                let c = i32::from(*coefficient);
                let bit = (((LOWER - c) & (c - UPPER)) as u32) >> 31;
                value |= bit << j;
            }
            *byte = value as u8;
        }
    }

    /// BC 的 `FromMsg`：每個位元為 1 時係數是 (q + 1)/2，否則是 0。常數時間：以遮罩代替分支。
    pub(crate) fn from_msg(message: &[u8]) -> Self {
        let mut poly = Self::zero();
        for (eight, byte) in poly.coeffs.chunks_exact_mut(8).zip(message) {
            for (j, coefficient) in eight.iter_mut().enumerate() {
                let mask = -(((byte >> j) & 1) as i16);
                *coefficient = mask & ((Q + 1) / 2);
            }
        }
        poly
    }

    /// BC 的 `CheckModulus`：編碼裡每個 12 位元的係數都小於 q 時為真。變動時間：只能用於
    /// 公開值，用於公開的封裝金鑰。
    pub(crate) fn check_modulus(bytes: &[u8]) -> bool {
        bytes.chunks_exact(3).all(|b| {
            let (a0, a1, a2) = (u16::from(b[0]), u16::from(b[1]), u16::from(b[2]));
            let c0 = (a0 | (a1 << 8)) & 0xFFF;
            let c1 = ((a1 >> 4) | (a2 << 4)) & 0xFFF;
            c0 < Q as u16 && c1 < Q as u16
        })
    }
}
