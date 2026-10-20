// The intrinsics are unsafe before Rust 1.87 and safe inside these functions after it.
#![allow(unused_unsafe)]

use super::kernels::{load, mul2x2, store};
use crate::reduce::Reducer;
#[cfg(target_arch = "x86")]
use core::arch::x86::{
    __m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_slli_si128, _mm_srli_si128, _mm_xor_si128,
};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_slli_si128, _mm_srli_si128, _mm_xor_si128,
};
use tc_runtime::intrinsics::x86::Pclmulqdq;
use tc_zeroize::Zeroize;

/// The largest size with a kernel of its own, as BC's `Size10`.
pub(crate) const MAX_SIZE: usize = 10;

/// BC's X86.V128 `Size1` to `Size10`: `z = x · y mod f` for one to [`MAX_SIZE`] limbs, by the
/// kernel of [`impl_mul`] for that size. Constant time.
pub(crate) fn multiply(proof: Pclmulqdq, reducer: &Reducer, x: &[u64], y: &[u64], z: &mut [u64]) {
    let size = x.len();
    let mut buffer = [0; 2 * MAX_SIZE];
    let tt = &mut buffer[..2 * size];
    impl_mul(proof, x, y, tt);
    reducer.reduce(tt, z);
    tt.zeroize();
}

/// BC's `Kernels.ImplMul1` to `ImplMul10`: `zz = x · y` unreduced, the operands of one
/// length up to [`MAX_SIZE`] and `zz` of twice it, each size written out as Karatsuba over
/// the smaller ones. Constant time: the work depends on the length alone.
pub(crate) fn impl_mul(_proof: Pclmulqdq, x: &[u64], y: &[u64], zz: &mut [u64]) {
    let len = x.len();
    assert_eq!(y.len(), len, "invalid operand length");
    assert_eq!(zz.len(), len * 2, "invalid product length");
    // SAFETY: the proof shows the CPU has PCLMULQDQ, and every such CPU has SSE2.
    let lanes = unsafe {
        match len {
            1 => mul1(x, y),
            2 => mul2(x, y),
            3 => mul3(x, y),
            4 => mul4(x, y),
            5 => mul5(x, y),
            6 => mul6(x, y),
            7 => mul7(x, y),
            8 => mul8(x, y),
            9 => mul9(x, y),
            10 => mul10(x, y),
            _ => panic!("no kernel for {len} limbs"),
        }
    };
    for (i, lane) in lanes[..len].iter().enumerate() {
        // SAFETY: as above; `zz` holds `len` lanes.
        unsafe { store(zz, i, *lane) };
    }
}

type Lanes = [__m128i; MAX_SIZE];

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn pack(lo: u64, hi: u64) -> __m128i {
    unsafe { _mm_set_epi64x(hi as i64, lo as i64) }
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn xor(a: __m128i, b: __m128i) -> __m128i {
    unsafe { _mm_xor_si128(a, b) }
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn up(a: __m128i) -> __m128i {
    unsafe { _mm_slli_si128::<8>(a) }
}

#[inline]
#[target_feature(enable = "sse2")]
unsafe fn down(a: __m128i) -> __m128i {
    unsafe { _mm_srli_si128::<8>(a) }
}

// The product of the two halves of a lane packed as (x, y).
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn clmul(xy: __m128i) -> __m128i {
    unsafe { _mm_clmulepi64_si128::<0x01>(xy, xy) }
}

// M_ij = (x_i + x_j)(y_i + y_j) + P_ii + P_jj, the cross term x_i·y_j + x_j·y_i, from the
// lanes packed as (x, y) and their diagonal products.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn middle(xy_i: __m128i, xy_j: __m128i, p_i: __m128i, p_j: __m128i) -> __m128i {
    unsafe { xor(xor(clmul(xor(xy_i, xy_j)), p_i), p_j) }
}

// The same for the three lanes of block products.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn block_middle(q: [__m128i; 3], p_i: [__m128i; 3], p_j: [__m128i; 3]) -> [__m128i; 3] {
    unsafe {
        [
            xor(xor(q[0], p_i[0]), p_j[0]),
            xor(xor(q[1], p_i[1]), p_j[1]),
            xor(xor(q[2], p_i[2]), p_j[2]),
        ]
    }
}

#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn lanes<const N: usize>(head: [__m128i; N]) -> Lanes {
    unsafe {
        let mut lanes = [pack(0, 0); MAX_SIZE];
        lanes[..N].copy_from_slice(&head);
        lanes
    }
}

// BC's `Mul3x3`: the diagonals P_ii = x_i·y_i and the cross products
// Q_ij = (x_i + x_j)(y_i + y_j), whose middle terms are M_ij = Q_ij + P_ii + P_jj; six CLMULs
// against nine.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul3x3(x: [u64; 3], y: [u64; 3]) -> [__m128i; 3] {
    unsafe {
        let xy = [pack(x[0], y[0]), pack(x[1], y[1]), pack(x[2], y[2])];
        let p = [clmul(xy[0]), clmul(xy[1]), clmul(xy[2])];
        let m01 = middle(xy[0], xy[1], p[0], p[1]);
        let m02 = middle(xy[0], xy[2], p[0], p[2]);
        let m12 = middle(xy[1], xy[2], p[1], p[2]);
        [
            xor(p[0], up(m01)),
            xor(xor(p[1], down(m01)), xor(m02, up(m12))),
            xor(p[2], down(m12)),
        ]
    }
}

// BC's `Mul4x4`: a 2 + 2 Karatsuba of three `Mul2x2`s, nine CLMULs.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul4x4(x: [u64; 4], y: [u64; 4]) -> [__m128i; 4] {
    unsafe {
        let (x_lo, x_hi) = (pack(x[0], x[1]), pack(x[2], x[3]));
        let (y_lo, y_hi) = (pack(y[0], y[1]), pack(y[2], y[3]));
        let (z0w0, z0w1) = mul2x2(x_lo, y_lo);
        let (z2w0, z2w1) = mul2x2(x_hi, y_hi);
        let (zmw0, zmw1) = mul2x2(xor(x_lo, x_hi), xor(y_lo, y_hi));
        let t = xor(z0w1, z2w0);
        [z0w0, xor(t, xor(zmw0, z0w0)), xor(t, xor(zmw1, z2w1)), z2w1]
    }
}

// BC's `Mul5x5`: Mul3x3's pattern over five limbs, fifteen CLMULs against 25; the middle
// terms that land on one position are folded first.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul5x5(x: [u64; 5], y: [u64; 5]) -> [__m128i; 5] {
    unsafe {
        let xy = [
            pack(x[0], y[0]),
            pack(x[1], y[1]),
            pack(x[2], y[2]),
            pack(x[3], y[3]),
            pack(x[4], y[4]),
        ];
        let p = [
            clmul(xy[0]),
            clmul(xy[1]),
            clmul(xy[2]),
            clmul(xy[3]),
            clmul(xy[4]),
        ];
        let m01 = middle(xy[0], xy[1], p[0], p[1]);
        let m02 = middle(xy[0], xy[2], p[0], p[2]);
        let m24 = middle(xy[2], xy[4], p[2], p[4]);
        let m34 = middle(xy[3], xy[4], p[3], p[4]);
        let m03_12 = xor(
            middle(xy[0], xy[3], p[0], p[3]),
            middle(xy[1], xy[2], p[1], p[2]),
        );
        let m04_13 = xor(
            middle(xy[0], xy[4], p[0], p[4]),
            middle(xy[1], xy[3], p[1], p[3]),
        );
        let m14_23 = xor(
            middle(xy[1], xy[4], p[1], p[4]),
            middle(xy[2], xy[3], p[2], p[3]),
        );
        [
            xor(p[0], up(m01)),
            xor(xor(p[1], down(m01)), xor(m02, up(m03_12))),
            xor(xor(p[2], down(m03_12)), xor(m04_13, up(m14_23))),
            xor(xor(p[3], down(m14_23)), xor(m24, up(m34))),
            xor(p[4], down(m34)),
        ]
    }
}

// BC's `Mul7x7`: a 4 + 3 Karatsuba, the high half padded with a zero limb; 24 CLMULs.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul7x7(x: [u64; 7], y: [u64; 7]) -> [__m128i; 7] {
    unsafe {
        let [z0w0, z0w1, z0w2, z0w3] = mul4x4([x[0], x[1], x[2], x[3]], [y[0], y[1], y[2], y[3]]);
        let [zmw0, zmw1, zmw2, zmw3] = mul4x4(
            [x[0] ^ x[4], x[1] ^ x[5], x[2] ^ x[6], x[3]],
            [y[0] ^ y[4], y[1] ^ y[5], y[2] ^ y[6], y[3]],
        );
        let [z2w0, z2w1, z2w2] = mul3x3([x[4], x[5], x[6]], [y[4], y[5], y[6]]);
        let t0 = xor(z0w2, z2w0);
        let t1 = xor(z0w3, z2w1);
        [
            z0w0,
            z0w1,
            xor(t0, xor(zmw0, z0w0)),
            xor(t1, xor(zmw1, z0w1)),
            xor(t0, xor(zmw2, z2w2)),
            xor(t1, zmw3),
            z2w2,
        ]
    }
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul1(x: &[u64], y: &[u64]) -> Lanes {
    unsafe { lanes([clmul(pack(x[0], y[0]))]) }
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul2(x: &[u64], y: &[u64]) -> Lanes {
    unsafe {
        let (w0, w1) = mul2x2(load(x, 0), load(y, 0));
        lanes([w0, w1])
    }
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul3(x: &[u64], y: &[u64]) -> Lanes {
    unsafe { lanes(mul3x3([x[0], x[1], x[2]], [y[0], y[1], y[2]])) }
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul4(x: &[u64], y: &[u64]) -> Lanes {
    unsafe { lanes(mul4x4([x[0], x[1], x[2], x[3]], [y[0], y[1], y[2], y[3]])) }
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul5(x: &[u64], y: &[u64]) -> Lanes {
    unsafe {
        lanes(mul5x5(
            [x[0], x[1], x[2], x[3], x[4]],
            [y[0], y[1], y[2], y[3], y[4]],
        ))
    }
}

// BC's `ImplMul6`: a 3 + 3 Karatsuba of three `Mul3x3`s, eighteen CLMULs.
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul6(x: &[u64], y: &[u64]) -> Lanes {
    unsafe {
        let [z0w0, z0w1, z0w2] = mul3x3([x[0], x[1], x[2]], [y[0], y[1], y[2]]);
        let [z2w0, z2w1, z2w2] = mul3x3([x[3], x[4], x[5]], [y[3], y[4], y[5]]);
        let [zmw0, zmw1, zmw2] = mul3x3(
            [x[0] ^ x[3], x[1] ^ x[4], x[2] ^ x[5]],
            [y[0] ^ y[3], y[1] ^ y[4], y[2] ^ y[5]],
        );
        let mid0 = xor(xor(zmw0, z0w0), z2w0);
        let mid1 = xor(xor(zmw1, z0w1), z2w1);
        let mid2 = xor(xor(zmw2, z0w2), z2w2);
        lanes([
            z0w0,
            xor(z0w1, up(mid0)),
            xor(xor(z0w2, down(mid0)), up(mid1)),
            xor(xor(z2w0, down(mid1)), up(mid2)),
            xor(z2w1, down(mid2)),
            z2w2,
        ])
    }
}

#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul7(x: &[u64], y: &[u64]) -> Lanes {
    unsafe {
        lanes(mul7x7(
            [x[0], x[1], x[2], x[3], x[4], x[5], x[6]],
            [y[0], y[1], y[2], y[3], y[4], y[5], y[6]],
        ))
    }
}

// BC's `ImplMul8`: a 4 + 4 Karatsuba of three `Mul4x4`s, 27 CLMULs.
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul8(x: &[u64], y: &[u64]) -> Lanes {
    unsafe {
        let [z0w0, z0w1, z0w2, z0w3] = mul4x4([x[0], x[1], x[2], x[3]], [y[0], y[1], y[2], y[3]]);
        let [z2w0, z2w1, z2w2, z2w3] = mul4x4([x[4], x[5], x[6], x[7]], [y[4], y[5], y[6], y[7]]);
        let [zmw0, zmw1, zmw2, zmw3] = mul4x4(
            [x[0] ^ x[4], x[1] ^ x[5], x[2] ^ x[6], x[3] ^ x[7]],
            [y[0] ^ y[4], y[1] ^ y[5], y[2] ^ y[6], y[3] ^ y[7]],
        );
        let t0 = xor(z0w2, z2w0);
        let t1 = xor(z0w3, z2w1);
        lanes([
            z0w0,
            z0w1,
            xor(t0, xor(zmw0, z0w0)),
            xor(t1, xor(zmw1, z0w1)),
            xor(t0, xor(zmw2, z2w2)),
            xor(t1, xor(zmw3, z2w3)),
            z2w2,
            z2w3,
        ])
    }
}

fn block(w: &[u64], i: usize) -> [u64; 3] {
    [w[3 * i], w[3 * i + 1], w[3 * i + 2]]
}

fn block_sum(w: &[u64], i: usize, j: usize) -> [u64; 3] {
    let (a, b) = (block(w, i), block(w, j));
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2]]
}

// BC's `ImplMul9`: Mul3x3's pattern over three blocks of three limbs, six `Mul3x3`s and 36
// CLMULs; a block product at an odd position straddles four lanes.
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul9(x: &[u64], y: &[u64]) -> Lanes {
    unsafe {
        let p = [
            mul3x3(block(x, 0), block(y, 0)),
            mul3x3(block(x, 1), block(y, 1)),
            mul3x3(block(x, 2), block(y, 2)),
        ];
        let m01 = block_middle(mul3x3(block_sum(x, 0, 1), block_sum(y, 0, 1)), p[0], p[1]);
        let m02 = block_middle(mul3x3(block_sum(x, 0, 2), block_sum(y, 0, 2)), p[0], p[2]);
        let m12 = block_middle(mul3x3(block_sum(x, 1, 2), block_sum(y, 1, 2)), p[1], p[2]);
        lanes([
            p[0][0],
            xor(p[0][1], up(m01[0])),
            xor(xor(p[0][2], down(m01[0])), up(m01[1])),
            xor(xor(p[1][0], m02[0]), xor(down(m01[1]), up(m01[2]))),
            xor(xor(p[1][1], m02[1]), xor(down(m01[2]), up(m12[0]))),
            xor(xor(p[1][2], m02[2]), xor(down(m12[0]), up(m12[1]))),
            xor(p[2][0], xor(down(m12[1]), up(m12[2]))),
            xor(p[2][1], down(m12[2])),
            p[2][2],
        ])
    }
}

// BC's `ImplMul10`: 5 + 5 schoolbook of four `Mul5x5`s, 60 CLMULs, which BC prefers to the
// 45 of Karatsuba for its flatter data flow. The cross products land five limbs up, half a
// lane, so they are shifted in across lane boundaries.
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul10(x: &[u64], y: &[u64]) -> Lanes {
    unsafe {
        let (x_lo, x_hi) = (
            [x[0], x[1], x[2], x[3], x[4]],
            [x[5], x[6], x[7], x[8], x[9]],
        );
        let (y_lo, y_hi) = (
            [y[0], y[1], y[2], y[3], y[4]],
            [y[5], y[6], y[7], y[8], y[9]],
        );
        let a = mul5x5(x_lo, y_lo);
        let d = mul5x5(x_hi, y_hi);
        let b = mul5x5(x_lo, y_hi);
        let c = mul5x5(x_hi, y_lo);
        // bc starts at limb 5, the high half of lane 2.
        let mut out = [a[0], a[1], a[2], a[3], a[4], d[0], d[1], d[2], d[3], d[4]];
        for i in 0..5 {
            let bc = xor(b[i], c[i]);
            out[2 + i] = xor(out[2 + i], up(bc));
            out[3 + i] = xor(out[3 + i], down(bc));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::scalar::kernels::{schoolbook, words};
    use super::{MAX_SIZE, impl_mul};
    use tc_runtime::intrinsics::x86::Pclmulqdq;

    #[test]
    fn every_size_kernel_matches_a_bit_by_bit_schoolbook() {
        let Some(proof) = Pclmulqdq::detect() else {
            return;
        };
        let mut state = 0x5123_5123_5123_5123;
        for len in 1..=MAX_SIZE {
            for _ in 0..32 {
                let x = words(len, &mut state);
                let y = words(len, &mut state);
                let mut zz = alloc::vec![0; 2 * len];
                impl_mul(proof, &x, &y, &mut zz);
                assert_eq!(zz, schoolbook(&x, &y), "len = {len}");
            }
        }
    }
}
