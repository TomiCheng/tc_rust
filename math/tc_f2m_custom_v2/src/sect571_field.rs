// BC's `SecT571Field`: GF(2^571) modulo x^571 + x^10 + x^5 + x^2 + 1, on nine limbs.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;

use crate::interleave::{expand64_to128, unshuffle, unshuffle_pair};
#[cfg(target_arch = "x86_64")]
use tc_runtime::intrinsics::x86::Bmi2X64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use tc_runtime::intrinsics::x86::Pclmulqdq;
use tc_zeroize::Zeroize;

const M59: u64 = u64::MAX >> 5;
const ROOT_Z: [u64; 9] = [
    0x2BE1_195F_08CA_FB99,
    0x95F0_8CAF_8465_7C23,
    0xCAF8_4657_C232_BE11,
    0x657C_232B_E119_5F08,
    0xF846_57C2_308C_AF84,
    0x7C23_2BE1_195F_08CA,
    0xBE11_95F0_8CAF_8465,
    0x5F08_CAF8_4657_C232,
    0x0784_657C_232B_E119,
];

pub(crate) fn add(x: &[u64; 9], y: &[u64; 9]) -> [u64; 9] {
    let mut z = *x;
    for (z, y) in z.iter_mut().zip(y) {
        *z ^= y;
    }
    z
}

// x^(2^571 - 2) by Itoh–Tsujii, on the bases { 2, 3, 5 } of 570 = 2·3·5·19; zero for zero.
pub(crate) fn invert(x: &[u64; 9]) -> [u64; 9] {
    let mut t2 = square(x);
    // 5 | 570
    let mut t0 = square(&t2);
    let mut t1 = square(&t0);
    t0 = multiply(&t0, &t1);
    t1 = square_n(&t0, 2);
    t0 = multiply(&t0, &t1);
    t0 = multiply(&t0, &t2);
    // 3 | 114
    t1 = square_n(&t0, 5);
    t0 = multiply(&t0, &t1);
    t1 = square_n(&t1, 5);
    t0 = multiply(&t0, &t1);
    // 2 | 38
    t1 = square_n(&t0, 15);
    t2 = multiply(&t0, &t1);
    // ! {2, 3, 5} | 19
    t0 = square_n(&t2, 30);
    t1 = square_n(&t0, 30);
    t0 = multiply(&t0, &t1);
    // 3 | 9, 3
    for n in [60, 180] {
        t1 = square_n(&t0, n);
        t0 = multiply(&t0, &t1);
        t1 = square_n(&t1, n);
        t0 = multiply(&t0, &t1);
    }
    let z = multiply(&t0, &t2);
    t0.zeroize();
    t1.zeroize();
    t2.zeroize();
    z
}

// x = E(z)^2 + z·O(z)^2 for E and O made of its even and odd bits, so sqrt(x) = E + sqrt(z)·O.
pub(crate) fn sqrt(x: &[u64; 9]) -> [u64; 9] {
    let mut odd = [0; 9];
    let mut even = [0; 9];
    for i in 0..4 {
        [odd[i], even[i]] = unshuffle_pair(x[2 * i], x[2 * i + 1]);
    }
    [odd[4], even[4]] = unshuffle(x[8]);
    let z = add(&multiply(&odd, &ROOT_Z), &even);
    odd.zeroize();
    even.zeroize();
    z
}

// x + x^4 + x^16 + ... + x^(4^285), which m = 571 being odd allows.
pub(crate) fn half_trace(x: &[u64; 9]) -> [u64; 9] {
    let mut z = *x;
    for _ in (1..571).step_by(2) {
        z = add(&square(&square(&z)), x);
    }
    z
}

pub(crate) fn multiply(x: &[u64; 9], y: &[u64; 9]) -> [u64; 9] {
    let mut tt = impl_multiply(Mulw::detect(), x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u64; 9]) -> [u64; 9] {
    let mut tt = impl_square(x);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square_n(x: &[u64; 9], n: usize) -> [u64; 9] {
    debug_assert!(n > 0);
    let mut z = square(x);
    for _ in 1..n {
        z = square(&z);
    }
    z
}

// The bits of nonzero trace are 0, 561 and 569.
pub(crate) fn trace(x: &[u64; 9]) -> u8 {
    ((x[0] ^ (x[8] >> 49) ^ (x[8] >> 57)) & 1) as u8
}

fn reduce(xx: &[u64; 18]) -> [u64; 9] {
    let high = |u: u64| (u >> 59) ^ (u >> 57) ^ (u >> 54) ^ (u >> 49);
    let low = |u: u64| (u << 5) ^ (u << 7) ^ (u << 10) ^ (u << 15);

    let mut z = [0; 9];
    let xx09 = xx[9] ^ high(xx[17]);
    let mut v = xx[8] ^ low(xx[17]);
    for i in (10..=16).rev() {
        z[i - 8] = v ^ high(xx[i]);
        v = xx[i - 9] ^ low(xx[i]);
    }
    z[1] = v ^ high(xx09);
    v = xx[0] ^ low(xx09);

    let t = z[8] >> 59;
    z[0] = v ^ t ^ (t << 2) ^ (t << 5) ^ (t << 10);
    z[8] &= M59;
    z
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

// BC's Karatsuba over the nine whole limbs: the diagonal products spread across the lanes,
// then the cross terms (x_i + x_j)(y_i + y_j) added where they land.
fn impl_multiply(kernel: Mulw, x: &[u64; 9], y: &[u64; 9]) -> [u64; 18] {
    let mut u = [0; 16];
    let mut zz = [0; 18];

    for i in 0..9 {
        impl_mulw_acc(kernel, &mut u, x[i], y[i], &mut zz[2 * i..]);
    }

    let (mut v0, mut v1) = (zz[0], zz[1]);
    for i in 1..9 {
        v0 ^= zz[2 * i];
        zz[i] = v0 ^ v1;
        v1 ^= zz[2 * i + 1];
    }
    let w = v0 ^ v1;
    for i in 0..9 {
        zz[9 + i] = zz[i] ^ w;
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
        (0, 7, 7),
        (1, 6, 7),
        (2, 5, 7),
        (3, 4, 7),
        (0, 8, 8),
        (1, 7, 8),
        (2, 6, 8),
        (3, 5, 8),
        (1, 8, 9),
        (2, 7, 9),
        (3, 6, 9),
        (4, 5, 9),
        (2, 8, 10),
        (3, 7, 10),
        (4, 6, 10),
        (3, 8, 11),
        (4, 7, 11),
        (5, 6, 11),
        (4, 8, 12),
        (5, 7, 12),
        (5, 8, 13),
        (6, 7, 13),
        (6, 8, 14),
        (7, 8, 15),
    ] {
        impl_mulw_acc(kernel, &mut u, x[i] ^ x[j], y[i] ^ y[j], &mut zz[at..]);
    }

    u.zeroize();
    zz
}

// Adds the 128-bit product of two words into `z[0]` and `z[1]`. By CLMUL constant time; by
// the scalar table variable time, the table indexed by bits of `x`, the cache-timing side
// channel BC accepts without CLMUL, with BC's repair for the bits the table's shifts drop.
#[cfg_attr(
    not(any(target_arch = "x86", target_arch = "x86_64")),
    allow(unused_variables)
)]
fn impl_mulw_acc(kernel: Mulw, u: &mut [u64; 16], x: u64, y: u64, z: &mut [u64]) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Mulw::Clmul(proof) = kernel {
        let [z0, z1] = x86::mulw(proof, x, y);
        z[0] ^= z0;
        z[1] ^= z1;
        return;
    }

    let (mut h, mut m, mut n) = (0, x, y);
    u[1] = y;
    for i in (2..16).step_by(2) {
        let u_i = u[i / 2] << 1;
        u[i] = u_i;
        u[i + 1] = u_i ^ y;
        m = (m & 0xFEFE_FEFE_FEFE_FEFE) >> 1;
        h ^= m & ((n as i64 >> 63) as u64);
        n <<= 1;
    }

    let mut l = u[(x & 15) as usize] ^ (u[((x >> 4) & 15) as usize] << 4);
    for k in (8..=56).rev().step_by(8) {
        let j = x >> k;
        let g = u[(j & 15) as usize] ^ (u[((j >> 4) & 15) as usize] << 4);
        l ^= g << k;
        h ^= g >> (64 - k);
    }

    z[0] ^= l;
    z[1] ^= h;
}

// Bit i to bit 2i: by PDEP where the CPU has BMI2, else by the scalar Interleave steps.
fn impl_square(x: &[u64; 9]) -> [u64; 18] {
    let mut zz = [0; 18];
    #[cfg(target_arch = "x86_64")]
    if let Some(proof) = Bmi2X64::detect() {
        crate::interleave::x86::expand(proof, x, &mut zz);
        return zz;
    }
    for (i, &word) in x.iter().enumerate() {
        [zz[2 * i], zz[2 * i + 1]] = expand64_to128(word);
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
        let mut state = 0x0571_0571_0571_0571_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let mut x = [0; 9].map(|_: u64| next());
            let mut y = [0; 9].map(|_: u64| next());
            x[8] >>= 5;
            y[8] >>= 5;
            assert_eq!(
                impl_multiply(Mulw::Clmul(proof), &x, &y),
                impl_multiply(Mulw::Scalar, &x, &y)
            );
        }
    }
}
