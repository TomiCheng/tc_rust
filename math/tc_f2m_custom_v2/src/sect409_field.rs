// BC's `SecT409Field`: GF(2^409) modulo x^409 + x^87 + 1, on seven limbs.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;

use crate::interleave::{expand64_to128, unshuffle, unshuffle_pair};
#[cfg(target_arch = "x86_64")]
use tc_runtime::intrinsics::x86::Bmi2X64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use tc_runtime::intrinsics::x86::Pclmulqdq;
use tc_zeroize::Zeroize;

const M25: u64 = u64::MAX >> 39;
const M59: u64 = u64::MAX >> 5;

pub(crate) fn add(x: &[u64; 7], y: &[u64; 7]) -> [u64; 7] {
    let mut z = *x;
    for (z, y) in z.iter_mut().zip(y) {
        *z ^= y;
    }
    z
}

// x^(2^409 - 2) by Itoh–Tsujii, on the bases { 2, 3 } of 408 = 3·2^3·17; zero for zero.
pub(crate) fn invert(x: &[u64; 7]) -> [u64; 7] {
    let mut t0 = square(x);
    // 3 | 408
    let mut t1 = square_n(&t0, 1);
    t0 = multiply(&t0, &t1);
    t1 = square_n(&t1, 1);
    t0 = multiply(&t0, &t1);
    // 2 | 136, 68
    for n in [3, 6] {
        t1 = square_n(&t0, n);
        t0 = multiply(&t0, &t1);
    }
    // 2 | 34
    t1 = square_n(&t0, 12);
    let mut t2 = multiply(&t0, &t1);
    // ! {2, 3} | 17
    t0 = square_n(&t2, 24);
    t1 = square_n(&t0, 24);
    t0 = multiply(&t0, &t1);
    // 2 | 8, 4, 2
    for n in [48, 96, 192] {
        t1 = square_n(&t0, n);
        t0 = multiply(&t0, &t1);
    }
    let z = multiply(&t0, &t2);
    t0.zeroize();
    t1.zeroize();
    t2.zeroize();
    z
}

// x = E(z)^2 + z·O(z)^2 for E and O made of its even and odd bits, so sqrt(x) = E + sqrt(z)·O,
// where sqrt(z) = z^44 + z^13.
pub(crate) fn sqrt(x: &[u64; 7]) -> [u64; 7] {
    let [c0, e0] = unshuffle_pair(x[0], x[1]);
    let [c1, e1] = unshuffle_pair(x[2], x[3]);
    let [c2, e2] = unshuffle_pair(x[4], x[5]);
    let [c3, e3] = unshuffle(x[6]);
    [
        e0 ^ (c0 << 44),
        e1 ^ (c1 << 44) ^ (c0 >> 20),
        e2 ^ (c2 << 44) ^ (c1 >> 20),
        e3 ^ (c3 << 44) ^ (c2 >> 20) ^ (c0 << 13),
        (c3 >> 20) ^ (c1 << 13) ^ (c0 >> 51),
        (c2 << 13) ^ (c1 >> 51),
        (c3 << 13) ^ (c2 >> 51),
    ]
}

// x + x^4 + x^16 + ... + x^(4^204), which m = 409 being odd allows.
pub(crate) fn half_trace(x: &[u64; 7]) -> [u64; 7] {
    let mut z = *x;
    for _ in (1..409).step_by(2) {
        z = add(&square(&square(&z)), x);
    }
    z
}

pub(crate) fn multiply(x: &[u64; 7], y: &[u64; 7]) -> [u64; 7] {
    let mut tt = impl_multiply(Mulw::detect(), x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u64; 7]) -> [u64; 7] {
    let mut tt = impl_square(x);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square_n(x: &[u64; 7], n: usize) -> [u64; 7] {
    debug_assert!(n > 0);
    let mut tt = impl_square(x);
    let mut z = reduce(&tt);
    for _ in 1..n {
        tt = impl_square(&z);
        z = reduce(&tt);
    }
    tt.zeroize();
    z
}

// The only bit of nonzero trace is 0.
pub(crate) fn trace(x: &[u64; 7]) -> u8 {
    (x[0] & 1) as u8
}

// The product's fourteenth limb is always zero and is not read.
fn reduce(xx: &[u64; 14]) -> [u64; 7] {
    let [
        mut x0,
        mut x1,
        mut x2,
        mut x3,
        mut x4,
        mut x5,
        mut x6,
        mut x7,
    ] = [xx[0], xx[1], xx[2], xx[3], xx[4], xx[5], xx[6], xx[7]];

    let fold = |u: u64, lo: &mut u64, mid: &mut u64, hi: &mut u64| {
        *lo ^= u << 39;
        *mid ^= (u >> 25) ^ (u << 62);
        *hi ^= u >> 2;
    };
    fold(xx[12], &mut x5, &mut x6, &mut x7);
    fold(xx[11], &mut x4, &mut x5, &mut x6);
    fold(xx[10], &mut x3, &mut x4, &mut x5);
    fold(xx[9], &mut x2, &mut x3, &mut x4);
    fold(xx[8], &mut x1, &mut x2, &mut x3);
    let u = x7;
    fold(u, &mut x0, &mut x1, &mut x2);

    let t = x6 >> 25;
    [x0 ^ t, x1 ^ (t << 23), x2, x3, x4, x5, x6 & M25]
}

// The word product: by PCLMULQDQ where the CPU has it, which is constant time, else by the
// scalar table; picked once for each field product.
#[derive(Clone, Copy)]
enum Mulw {
    Scalar,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Clmul(Pclmulqdq),
}

impl Mulw {
    fn detect() -> Self {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if let Some(proof) = Pclmulqdq::detect() {
            return Self::Clmul(proof);
        }
        Self::Scalar
    }
}

// BC's Karatsuba over seven 59-bit pieces: the diagonal products spread across the lanes,
// then the cross terms (a_i + a_j)(b_i + b_j) added where they land.
fn impl_multiply(kernel: Mulw, x: &[u64; 7], y: &[u64; 7]) -> [u64; 14] {
    let (mut a, mut b) = (impl_expand(x), impl_expand(y));
    let mut u = [0; 8];
    let mut zz = [0; 14];

    for i in 0..7 {
        impl_mulw_acc(kernel, &mut u, a[i], b[i], &mut zz[2 * i..]);
    }

    let (mut v0, mut v1) = (zz[0], zz[1]);
    for i in 1..7 {
        v0 ^= zz[2 * i];
        zz[i] = v0 ^ v1;
        v1 ^= zz[2 * i + 1];
    }
    let w = v0 ^ v1;
    for i in 0..7 {
        zz[7 + i] = zz[i] ^ w;
    }

    for (i, j, at) in [
        (0, 1, 1),
        (0, 2, 2),
        (0, 3, 3),
        (1, 2, 3),
        (0, 4, 4),
        (1, 3, 4),
        (0, 5, 5),
        (1, 4, 5),
        (2, 3, 5),
        (0, 6, 6),
        (1, 5, 6),
        (2, 4, 6),
        (1, 6, 7),
        (2, 5, 7),
        (3, 4, 7),
        (2, 6, 8),
        (3, 5, 8),
        (3, 6, 9),
        (4, 5, 9),
        (4, 6, 10),
        (5, 6, 11),
    ] {
        impl_mulw_acc(kernel, &mut u, a[i] ^ a[j], b[i] ^ b[j], &mut zz[at..]);
    }
    impl_compact_ext(&mut zz);

    a.zeroize();
    b.zeroize();
    u.zeroize();
    zz
}

fn impl_expand(x: &[u64; 7]) -> [u64; 7] {
    [
        x[0] & M59,
        ((x[0] >> 59) ^ (x[1] << 5)) & M59,
        ((x[1] >> 54) ^ (x[2] << 10)) & M59,
        ((x[2] >> 49) ^ (x[3] << 15)) & M59,
        ((x[3] >> 44) ^ (x[4] << 20)) & M59,
        ((x[4] >> 39) ^ (x[5] << 25)) & M59,
        (x[5] >> 34) ^ (x[6] << 30),
    ]
}

// Adds the product of two 59-bit words, as two 59-bit pieces, into `z[0]` and `z[1]`. By
// CLMUL constant time; by the scalar table variable time, the table indexed by bits of `x`,
// the cache-timing side channel BC accepts without CLMUL.
#[cfg_attr(
    not(any(target_arch = "x86", target_arch = "x86_64")),
    allow(unused_variables)
)]
fn impl_mulw_acc(kernel: Mulw, u: &mut [u64; 8], x: u64, y: u64, z: &mut [u64]) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Mulw::Clmul(proof) = kernel {
        let [z0, z1] = x86::mulw(proof, x, y);
        z[0] ^= z0 & M59;
        z[1] ^= (z0 >> 59) ^ (z1 << 5);
        return;
    }

    u[1] = y;
    u[2] = u[1] << 1;
    u[3] = u[2] ^ y;
    u[4] = u[2] << 1;
    u[5] = u[4] ^ y;
    u[6] = u[3] << 1;
    u[7] = u[6] ^ y;

    let mut l = u[(x & 7) as usize] ^ (u[((x >> 3) & 7) as usize] << 3);
    let mut h = 0;
    for k in (6..=54).rev().step_by(6) {
        let j = x >> k;
        let g = u[(j & 7) as usize] ^ (u[((j >> 3) & 7) as usize] << 3);
        l ^= g << k;
        h ^= g >> (64 - k);
    }

    z[0] ^= l & M59;
    z[1] ^= (l >> 59) ^ (h << 5);
}

fn impl_compact_ext(zz: &mut [u64; 14]) {
    let z = *zz;
    *zz = [
        z[0] ^ (z[1] << 59),
        (z[1] >> 5) ^ (z[2] << 54),
        (z[2] >> 10) ^ (z[3] << 49),
        (z[3] >> 15) ^ (z[4] << 44),
        (z[4] >> 20) ^ (z[5] << 39),
        (z[5] >> 25) ^ (z[6] << 34),
        (z[6] >> 30) ^ (z[7] << 29),
        (z[7] >> 35) ^ (z[8] << 24),
        (z[8] >> 40) ^ (z[9] << 19),
        (z[9] >> 45) ^ (z[10] << 14),
        (z[10] >> 50) ^ (z[11] << 9),
        (z[11] >> 55) ^ (z[12] << 4) ^ (z[13] << 63),
        z[13] >> 1,
        0,
    ];
}

// Bit i to bit 2i: by PDEP where the CPU has BMI2, else by the scalar Interleave steps. The
// top limb holds 25 bits, so its low half suffices.
fn impl_square(x: &[u64; 7]) -> [u64; 14] {
    let mut zz = [0; 14];
    zz[12] = expand64_to128(x[6])[0];
    #[cfg(target_arch = "x86_64")]
    if let Some(proof) = Bmi2X64::detect() {
        crate::interleave::x86::expand(proof, &x[..6], &mut zz[..12]);
        return zz;
    }
    for i in 0..6 {
        [zz[2 * i], zz[2 * i + 1]] = expand64_to128(x[i]);
    }
    zz
}

#[cfg(all(test, any(target_arch = "x86", target_arch = "x86_64")))]
mod tests {
    use super::{Mulw, impl_multiply};
    use tc_runtime::intrinsics::x86::Pclmulqdq;

    #[test]
    fn the_clmul_product_is_the_scalar_one() {
        let Some(proof) = Pclmulqdq::detect() else {
            return;
        };
        let mut state = 0x0409_0409_0409_0409_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let mut x = [0; 7].map(|_: u64| next());
            let mut y = [0; 7].map(|_: u64| next());
            x[6] >>= 39;
            y[6] >>= 39;
            assert_eq!(
                impl_multiply(Mulw::Clmul(proof), &x, &y),
                impl_multiply(Mulw::Scalar, &x, &y)
            );
        }
    }
}
