#![allow(clippy::needless_range_loop)]

use tc_digest::{Digest, Xof};
use tc_keccak::ShakeDigest;
use tc_zeroize::Zeroize;

use crate::ntt;
use crate::reduce::{conditional_add_q, montgomery_reduce, reduce32};
use crate::rounding;

pub(crate) const N: usize = 256;
pub(crate) const Q: i32 = 8380417;
pub(crate) const D: u32 = 13;

const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

/// BC 的 `Poly`：256 個係數。
#[derive(Clone)]
pub(crate) struct Poly(pub(crate) [i32; N]);

impl Default for Poly {
    fn default() -> Self {
        Self([0; N])
    }
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

fn stream(bits: usize, seed: &[u8], nonce: u16) -> ShakeDigest {
    let mut xof = ShakeDigest::new(bits);
    xof.update(seed);
    xof.update(&nonce.to_le_bytes());
    xof
}

fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

impl Poly {
    pub(crate) fn add(&mut self, other: &Poly) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a += b;
        }
    }

    pub(crate) fn subtract(&mut self, other: &Poly) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a -= b;
        }
    }

    pub(crate) fn reduce(&mut self) {
        for a in &mut self.0 {
            *a = reduce32(*a);
        }
    }

    pub(crate) fn conditional_add_q(&mut self) {
        for a in &mut self.0 {
            *a = conditional_add_q(*a);
        }
    }

    pub(crate) fn ntt(&mut self) {
        ntt::ntt(&mut self.0);
    }

    pub(crate) fn inverse_ntt_to_mont(&mut self) {
        ntt::inverse_ntt_to_mont(&mut self.0);
    }

    pub(crate) fn shift_left(&mut self) {
        for a in &mut self.0 {
            *a <<= D;
        }
    }

    /// self = a ∘ b，Montgomery 乘法。常數時間。
    pub(crate) fn pointwise_montgomery(&mut self, a: &Poly, b: &Poly) {
        for i in 0..N {
            self.0[i] = montgomery_reduce(i64::from(a.0[i]) * i64::from(b.0[i]));
        }
    }

    /// self 拆成高位元 self 與低位元 low。常數時間。
    pub(crate) fn power2round(&mut self, low: &mut Poly) {
        for i in 0..N {
            (self.0[i], low.0[i]) = rounding::power2round(self.0[i]);
        }
    }

    /// self 拆成高位元 self 與低位元 low。常數時間。
    pub(crate) fn decompose(&mut self, low: &mut Poly, gamma2: i32) {
        for i in 0..N {
            (self.0[i], low.0[i]) = rounding::decompose(self.0[i], gamma2);
        }
    }

    /// 寫入提示並回傳 1 的個數。常數時間。
    pub(crate) fn make_hint(&mut self, a0: &Poly, a1: &Poly, gamma2: i32) -> usize {
        let mut count = 0;
        for i in 0..N {
            self.0[i] = rounding::make_hint(a0.0[i], a1.0[i], gamma2);
            count += self.0[i] as usize;
        }
        count
    }

    pub(crate) fn use_hint(&mut self, hint: &Poly, gamma2: i32) {
        for i in 0..N {
            self.0[i] = rounding::use_hint(self.0[i], hint.0[i], gamma2);
        }
    }

    /// BC 的 `CheckNorm`：有係數的絕對值不小於 bound。遇到第一個就停：FIPS 204 與參考實作都
    /// 接受透露是哪一個係數，因為每個係數超界的機率與秘密無關。
    pub(crate) fn check_norm(&self, bound: i32) -> bool {
        if bound > (Q - 1) / 8 {
            return true;
        }
        self.0.iter().any(|&a| {
            let t = a >> 31;
            a - (t & (2 * a)) >= bound
        })
    }

    /// BC 的 `UniformBlocks`（FIPS 204 的 RejNTTPoly）：從 SHAKE128(ρ ‖ nonce) 拒絕取樣出
    /// 小於 q 的係數。只用於公開的 ρ。
    pub(crate) fn uniform(&mut self, rho: &[u8], nonce: u16) {
        let mut xof = stream(128, rho, nonce);
        let mut buf = [0u8; 5 * SHAKE128_RATE + 2];
        let mut buflen = 5 * SHAKE128_RATE;
        xof.output(&mut buf[..buflen]);
        let mut count = reject_uniform(&mut self.0, 0, &buf[..buflen]);
        while count < N {
            let off = buflen % 3;
            for i in 0..off {
                buf[i] = buf[buflen - off + i];
            }
            xof.output(&mut buf[off..off + SHAKE128_RATE]);
            buflen = SHAKE128_RATE + off;
            count = reject_uniform(&mut self.0, count, &buf[..buflen]);
        }
    }

    /// BC 的 `UniformEta`（RejBoundedPoly）：從 SHAKE256(ρ′ ‖ nonce) 取 [−η, η] 的係數。拒絕
    /// 的次數依 ρ′ 而定，FIPS 204 也如此；其餘不依秘密分支。
    pub(crate) fn uniform_eta(&mut self, seed: &[u8], nonce: u16, eta: i32) {
        let blocks = if eta == 2 { 1 } else { 2 };
        let mut xof = stream(256, seed, nonce);
        let mut buf = [0u8; 2 * SHAKE256_RATE];
        xof.output(&mut buf[..blocks * SHAKE256_RATE]);
        let mut count = reject_eta(&mut self.0, 0, &buf[..blocks * SHAKE256_RATE], eta);
        while count < N {
            xof.output(&mut buf[..SHAKE256_RATE]);
            count = reject_eta(&mut self.0, count, &buf[..SHAKE256_RATE], eta);
        }
        buf.zeroize();
    }

    /// BC 的 `UniformGamma1`（ExpandMask 的一個多項式）。常數時間。
    pub(crate) fn uniform_gamma1(&mut self, seed: &[u8], nonce: u16, gamma1: i32) {
        let mut xof = stream(256, seed, nonce);
        let mut buf = [0u8; 5 * SHAKE256_RATE];
        xof.output(&mut buf);
        self.unpack_z(&buf, gamma1);
        buf.zeroize();
    }

    /// BC 的 `Challenge`（SampleInBall）：τ 個 ±1 的係數。依 c̃ 分支；c̃ 是簽章的一部分。
    pub(crate) fn challenge(&mut self, seed: &[u8], tau: usize) {
        let mut xof = ShakeDigest::new(256);
        xof.update(seed);
        let mut buf = [0u8; SHAKE256_RATE];
        xof.output(&mut buf);
        let mut signs = u64::from_le_bytes(buf[..8].try_into().expect("8 bytes"));
        let mut pos = 8;
        self.0 = [0; N];
        for i in N - tau..N {
            let b = loop {
                if pos >= SHAKE256_RATE {
                    xof.output(&mut buf);
                    pos = 0;
                }
                let b = usize::from(buf[pos]);
                pos += 1;
                if b <= i {
                    break b;
                }
            };
            self.0[i] = self.0[b];
            self.0[b] = 1 - 2 * (signs & 1) as i32;
            signs >>= 1;
        }
    }

    pub(crate) fn pack_t1(&self, out: &mut [u8]) {
        for i in 0..N / 4 {
            let c = &self.0[4 * i..4 * i + 4];
            let word =
                c[0] as u32 | (c[1] as u32) << 10 | (c[2] as u32) << 20 | (c[3] as u32) << 30;
            out[5 * i..5 * i + 4].copy_from_slice(&word.to_le_bytes());
            out[5 * i + 4] = (c[3] >> 2) as u8;
        }
    }

    pub(crate) fn unpack_t1(&mut self, a: &[u8]) {
        for i in 0..N / 4 {
            let t0 = le32(&a[5 * i..]);
            let t1 = u32::from(a[5 * i + 4]);
            self.0[4 * i] = (t0 & 0x3ff) as i32;
            self.0[4 * i + 1] = ((t0 >> 10) & 0x3ff) as i32;
            self.0[4 * i + 2] = ((t0 >> 20) & 0x3ff) as i32;
            self.0[4 * i + 3] = ((t0 >> 30 | t1 << 2) & 0x3ff) as i32;
        }
    }

    pub(crate) fn pack_t0(&self, out: &mut [u8]) {
        const M: i32 = 1 << (D - 1);
        for i in 0..N / 8 {
            let mut t = [0u32; 8];
            for j in 0..8 {
                t[j] = (M - self.0[8 * i + j]) as u32;
            }
            let r = &mut out[13 * i..13 * i + 13];
            r[0..4].copy_from_slice(&(t[0] | t[1] << 13 | t[2] << 26).to_le_bytes());
            r[4..8].copy_from_slice(&(t[2] >> 6 | t[3] << 7 | t[4] << 20).to_le_bytes());
            r[8..12]
                .copy_from_slice(&(t[4] >> 12 | t[5] << 1 | t[6] << 14 | t[7] << 27).to_le_bytes());
            r[12] = (t[7] >> 5) as u8;
        }
    }

    pub(crate) fn unpack_t0(&mut self, a: &[u8]) {
        const M: i32 = 1 << (D - 1);
        for i in 0..N / 8 {
            let a = &a[13 * i..13 * i + 13];
            let t0 = le32(&a[0..]);
            let t1 = le32(&a[4..]);
            let t2 = le32(&a[8..]);
            let t3 = u32::from(a[12]);
            let c = &mut self.0[8 * i..8 * i + 8];
            c[0] = M - (t0 & 0x1fff) as i32;
            c[1] = M - ((t0 >> 13) & 0x1fff) as i32;
            c[2] = M - ((t0 >> 26 | t1 << 6) & 0x1fff) as i32;
            c[3] = M - ((t1 >> 7) & 0x1fff) as i32;
            c[4] = M - ((t1 >> 20 | t2 << 12) & 0x1fff) as i32;
            c[5] = M - ((t2 >> 1) & 0x1fff) as i32;
            c[6] = M - ((t2 >> 14) & 0x1fff) as i32;
            c[7] = M - ((t2 >> 27 | t3 << 5) & 0x1fff) as i32;
        }
    }

    pub(crate) fn pack_eta(&self, out: &mut [u8], eta: i32) {
        if eta == 2 {
            for i in 0..N / 8 {
                let mut t = [0u8; 8];
                for j in 0..8 {
                    t[j] = (eta - self.0[8 * i + j]) as u8;
                }
                out[3 * i] = t[0] | t[1] << 3 | t[2] << 6;
                out[3 * i + 1] = t[2] >> 2 | t[3] << 1 | t[4] << 4 | t[5] << 7;
                out[3 * i + 2] = t[5] >> 1 | t[6] << 2 | t[7] << 5;
            }
        } else {
            for i in 0..N / 2 {
                let t0 = (eta - self.0[2 * i]) as u8;
                let t1 = (eta - self.0[2 * i + 1]) as u8;
                out[i] = t0 | t1 << 4;
            }
        }
    }

    pub(crate) fn unpack_eta(&mut self, a: &[u8], eta: i32) {
        if eta == 2 {
            for i in 0..N / 8 {
                let (b0, b1, b2) = (
                    i32::from(a[3 * i]),
                    i32::from(a[3 * i + 1]),
                    i32::from(a[3 * i + 2]),
                );
                let c = &mut self.0[8 * i..8 * i + 8];
                c[0] = eta - (b0 & 7);
                c[1] = eta - ((b0 >> 3) & 7);
                c[2] = eta - ((b0 >> 6 | b1 << 2) & 7);
                c[3] = eta - ((b1 >> 1) & 7);
                c[4] = eta - ((b1 >> 4) & 7);
                c[5] = eta - ((b1 >> 7 | b2 << 1) & 7);
                c[6] = eta - ((b2 >> 2) & 7);
                c[7] = eta - ((b2 >> 5) & 7);
            }
        } else {
            for i in 0..N / 2 {
                self.0[2 * i] = eta - i32::from(a[i] & 0x0f);
                self.0[2 * i + 1] = eta - i32::from(a[i] >> 4);
            }
        }
    }

    pub(crate) fn pack_z(&self, out: &mut [u8], gamma1: i32) {
        if gamma1 == 1 << 17 {
            for i in 0..N / 4 {
                let mut t = [0u32; 4];
                for j in 0..4 {
                    t[j] = (gamma1 - self.0[4 * i + j]) as u32;
                }
                let r = &mut out[9 * i..9 * i + 9];
                r[0..4].copy_from_slice(&(t[0] | t[1] << 18).to_le_bytes());
                r[4..8].copy_from_slice(&(t[1] >> 14 | t[2] << 4 | t[3] << 22).to_le_bytes());
                r[8] = (t[3] >> 10) as u8;
            }
        } else {
            for i in 0..N / 2 {
                let t0 = (gamma1 - self.0[2 * i]) as u32;
                let t1 = (gamma1 - self.0[2 * i + 1]) as u32;
                out[5 * i..5 * i + 4].copy_from_slice(&(t0 | t1 << 20).to_le_bytes());
                out[5 * i + 4] = (t1 >> 12) as u8;
            }
        }
    }

    pub(crate) fn unpack_z(&mut self, a: &[u8], gamma1: i32) {
        if gamma1 == 1 << 17 {
            for i in 0..N / 4 {
                let t0 = le32(&a[9 * i..]);
                let t1 = le32(&a[9 * i + 4..]);
                let t2 = u32::from(a[9 * i + 8]);
                let c = &mut self.0[4 * i..4 * i + 4];
                c[0] = gamma1 - (t0 & 0x3ffff) as i32;
                c[1] = gamma1 - ((t0 >> 18 | t1 << 14) & 0x3ffff) as i32;
                c[2] = gamma1 - ((t1 >> 4) & 0x3ffff) as i32;
                c[3] = gamma1 - ((t1 >> 22 | t2 << 10) & 0x3ffff) as i32;
            }
        } else {
            for i in 0..N / 2 {
                let t0 = le32(&a[5 * i..]);
                let t1 = u32::from(a[5 * i + 4]);
                self.0[2 * i] = gamma1 - (t0 & 0xfffff) as i32;
                self.0[2 * i + 1] = gamma1 - ((t0 >> 20 | t1 << 12) & 0xfffff) as i32;
            }
        }
    }

    pub(crate) fn pack_w1(&self, out: &mut [u8], gamma2: i32) {
        if gamma2 == (Q - 1) / 88 {
            for i in 0..N / 4 {
                let c = &self.0[4 * i..4 * i + 4];
                out[3 * i] = (c[0] | c[1] << 6) as u8;
                out[3 * i + 1] = (c[1] >> 2 | c[2] << 4) as u8;
                out[3 * i + 2] = (c[2] >> 4 | c[3] << 2) as u8;
            }
        } else {
            for i in 0..N / 2 {
                out[i] = (self.0[2 * i] | self.0[2 * i + 1] << 4) as u8;
            }
        }
    }
}

fn reject_uniform(coefficients: &mut [i32; N], mut count: usize, buf: &[u8]) -> usize {
    let mut pos = 0;
    while count < N && pos + 3 <= buf.len() {
        let t =
            (u32::from(buf[pos]) | u32::from(buf[pos + 1]) << 8 | u32::from(buf[pos + 2]) << 16)
                & 0x7f_ffff;
        pos += 3;
        if t < Q as u32 {
            coefficients[count] = t as i32;
            count += 1;
        }
    }
    count
}

fn reject_eta(coefficients: &mut [i32; N], mut count: usize, buf: &[u8], eta: i32) -> usize {
    for &byte in buf {
        if count >= N {
            break;
        }
        for t in [u32::from(byte & 0x0f), u32::from(byte >> 4)] {
            if count >= N {
                break;
            }
            if eta == 2 {
                if t < 15 {
                    let t = t - ((205 * t) >> 10) * 5;
                    coefficients[count] = 2 - t as i32;
                    count += 1;
                }
            } else if t < 9 {
                coefficients[count] = 4 - t as i32;
                count += 1;
            }
        }
    }
    count
}

/// 長度為 `length` 的零向量。
pub(crate) fn vector(length: usize) -> alloc::vec::Vec<Poly> {
    alloc::vec![Poly::default(); length]
}
