use crate::poly::Poly;
use crate::reduce::Q;

/// BC 的 `PolyVec`：k 個多項式，k 是 2、3 或 4；不用配置記憶體，多出的位置保持為零。
#[derive(Clone)]
pub(crate) struct PolyVec {
    polys: [Poly; 4],
    k: usize,
}

impl PolyVec {
    /// k 個零多項式。常數時間。
    pub(crate) fn zero(k: usize) -> Self {
        Self {
            polys: core::array::from_fn(|_| Poly::zero()),
            k,
        }
    }

    /// 由每個位置的多項式組成。常數時間：只依 k。
    pub(crate) fn from_fn(k: usize, mut poly: impl FnMut(usize) -> Poly) -> Self {
        let mut vector = Self::zero(k);
        for (i, slot) in vector.polys_mut().iter_mut().enumerate() {
            *slot = poly(i);
        }
        vector
    }

    /// 前 k 個多項式。常數時間。
    pub(crate) fn polys(&self) -> &[Poly] {
        &self.polys[..self.k]
    }

    /// 前 k 個多項式，可修改。常數時間。
    pub(crate) fn polys_mut(&mut self) -> &mut [Poly] {
        &mut self.polys[..self.k]
    }

    /// BC 的 `Ntt`。常數時間。
    pub(crate) fn ntt(&mut self) {
        self.polys_mut().iter_mut().for_each(Poly::ntt);
    }

    /// BC 的 `InverseNttToMont`。常數時間。
    pub(crate) fn inverse_ntt_to_mont(&mut self) {
        self.polys_mut()
            .iter_mut()
            .for_each(Poly::inverse_ntt_to_mont);
    }

    /// BC 的 `PointwiseAccountMontgomery`：NTT 領域的內積，再約化。常數時間。
    pub(crate) fn inner_product(a: &Self, b: &Self) -> Poly {
        let mut r = Poly::base_mul(&a.polys()[0], &b.polys()[0]);
        for (a, b) in a.polys().iter().zip(b.polys()).skip(1) {
            r.add(&Poly::base_mul(a, b));
        }
        r.reduce();
        r
    }

    /// BC 的 `Add`。常數時間。
    pub(crate) fn add(&mut self, other: &Self) {
        for (poly, other) in self.polys_mut().iter_mut().zip(other.polys()) {
            poly.add(other);
        }
    }

    /// BC 的 `Reduce`。常數時間。
    pub(crate) fn reduce(&mut self) {
        self.polys_mut().iter_mut().for_each(Poly::reduce);
    }

    /// BC 的 `CompressPolyVec`：k = 4 時每個係數壓成 11 位元，否則 10 位元。常數時間：除以 q
    /// 以乘法與位移代替。
    pub(crate) fn compress(&mut self, output: &mut [u8]) {
        let eleven = self.k == 4;
        let mut chunks: &mut [u8] = output;
        for poly in self.polys_mut() {
            poly.cond_sub_q();
            if eleven {
                for eight in poly.coeffs.chunks_exact(8) {
                    let t: [u16; 8] = core::array::from_fn(|k| {
                        let c = i64::from(eight[k]);
                        (((((c << 4) + (i64::from(Q) >> 8)) * 165_141_429) >> 32) & 0x7FF) as u16
                    });
                    let (out, rest) = core::mem::take(&mut chunks).split_at_mut(11);
                    out[0] = t[0] as u8;
                    out[1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
                    out[2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
                    out[3] = (t[2] >> 2) as u8;
                    out[4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
                    out[5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
                    out[6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
                    out[7] = (t[5] >> 1) as u8;
                    out[8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
                    out[9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
                    out[10] = (t[7] >> 3) as u8;
                    chunks = rest;
                }
            } else {
                for four in poly.coeffs.chunks_exact(4) {
                    let t: [u16; 4] = core::array::from_fn(|k| {
                        let c = i64::from(four[k]);
                        (((((c << 3) + (i64::from(Q) >> 8)) * 165_141_429) >> 32) & 0x3FF) as u16
                    });
                    let (out, rest) = core::mem::take(&mut chunks).split_at_mut(5);
                    out[0] = t[0] as u8;
                    out[1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                    out[2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                    out[3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                    out[4] = (t[3] >> 2) as u8;
                    chunks = rest;
                }
            }
        }
    }

    /// BC 的 `DecompressPolyVec`。常數時間：只有乘法與位移。
    pub(crate) fn decompress(k: usize, input: &[u8]) -> Self {
        let q = i32::from(Q);
        let mut vector = Self::zero(k);
        let eleven = k == 4;
        let per_poly = if eleven { 352 } else { 320 };
        for (poly, bytes) in vector
            .polys_mut()
            .iter_mut()
            .zip(input.chunks_exact(per_poly))
        {
            if eleven {
                for (eight, c) in poly.coeffs.chunks_exact_mut(8).zip(bytes.chunks_exact(11)) {
                    let c: [u16; 11] = core::array::from_fn(|i| u16::from(c[i]));
                    let t = [
                        c[0] | (c[1] << 8),
                        (c[1] >> 3) | (c[2] << 5),
                        (c[2] >> 6) | (c[3] << 2) | (c[4] << 10),
                        (c[4] >> 1) | (c[5] << 7),
                        (c[5] >> 4) | (c[6] << 4),
                        (c[6] >> 7) | (c[7] << 1) | (c[8] << 9),
                        (c[8] >> 2) | (c[9] << 6),
                        (c[9] >> 5) | (c[10] << 3),
                    ];
                    for (coefficient, t) in eight.iter_mut().zip(t) {
                        *coefficient = ((i32::from(t & 0x7FF) * q + 1024) >> 11) as i16;
                    }
                }
            } else {
                for (four, c) in poly.coeffs.chunks_exact_mut(4).zip(bytes.chunks_exact(5)) {
                    let c: [u16; 5] = core::array::from_fn(|i| u16::from(c[i]));
                    let t = [
                        c[0] | (c[1] << 8),
                        (c[1] >> 2) | (c[2] << 6),
                        (c[2] >> 4) | (c[3] << 4),
                        (c[3] >> 6) | (c[4] << 2),
                    ];
                    for (coefficient, t) in four.iter_mut().zip(t) {
                        *coefficient = ((i32::from(t & 0x3FF) * q + 512) >> 10) as i16;
                    }
                }
            }
        }
        vector
    }

    /// BC 的 `FromBytes`：每個多項式 384 個位元組。常數時間。
    pub(crate) fn from_bytes(k: usize, bytes: &[u8]) -> Self {
        Self::from_fn(k, |i| Poly::from_bytes(&bytes[384 * i..384 * (i + 1)]))
    }

    /// BC 的 `ToBytes`。常數時間。
    pub(crate) fn write_bytes(&mut self, output: &mut [u8]) {
        for (poly, out) in self
            .polys_mut()
            .iter_mut()
            .zip(output.chunks_exact_mut(384))
        {
            poly.write_bytes(out);
        }
    }
}
