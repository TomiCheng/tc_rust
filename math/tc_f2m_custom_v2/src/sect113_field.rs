// BC's `SecT113Field`: GF(2^113) modulo x^113 + x^9 + 1, on two limbs.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;

use crate::interleave::{expand64_to128, unshuffle_pair};
#[cfg(target_arch = "x86_64")]
use tc_runtime::intrinsics::x86::Bmi2X64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use tc_runtime::intrinsics::x86::Pclmulqdq;
use tc_zeroize::Zeroize;

const M49: u64 = u64::MAX >> 15;
const M57: u64 = u64::MAX >> 7;

pub(crate) fn add(x: &[u64; 2], y: &[u64; 2]) -> [u64; 2] {
    [x[0] ^ y[0], x[1] ^ y[1]]
}

// x^(2^113 - 2) by BC's Itoh–Tsujii chain; zero for zero.
pub(crate) fn invert(x: &[u64; 2]) -> [u64; 2] {
    let mut t0 = multiply(&square(x), x);
    t0 = multiply(&square(&t0), x);
    let mut t1 = multiply(&square_n(&t0, 3), &t0);
    t1 = multiply(&square(&t1), x);
    t0 = multiply(&square_n(&t1, 7), &t1);
    t1 = multiply(&square_n(&t0, 14), &t0);
    t0 = multiply(&square_n(&t1, 28), &t1);
    t1 = multiply(&square_n(&t0, 56), &t0);
    let z = square(&t1);
    t0.zeroize();
    t1.zeroize();
    z
}

// x = E(z)^2 + z·O(z)^2 for E and O made of its even and odd bits, so sqrt(x) = E + sqrt(z)·O,
// where sqrt(z) = z^57 + z^5.
pub(crate) fn sqrt(x: &[u64; 2]) -> [u64; 2] {
    let [c0, e0] = unshuffle_pair(x[0], x[1]);
    [e0 ^ (c0 << 57) ^ (c0 << 5), (c0 >> 7) ^ (c0 >> 59)]
}

// x + x^4 + x^16 + ... + x^(4^56), which m = 113 being odd allows.
pub(crate) fn half_trace(x: &[u64; 2]) -> [u64; 2] {
    let mut z = *x;
    for _ in (1..113).step_by(2) {
        z = add(&square(&square(&z)), x);
    }
    z
}

pub(crate) fn multiply(x: &[u64; 2], y: &[u64; 2]) -> [u64; 2] {
    let mut tt = impl_multiply(x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u64; 2]) -> [u64; 2] {
    let mut tt = impl_square(x);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square_n(x: &[u64; 2], n: usize) -> [u64; 2] {
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
pub(crate) fn trace(x: &[u64; 2]) -> u8 {
    (x[0] & 1) as u8
}

fn reduce(xx: &[u64; 4]) -> [u64; 2] {
    let [mut x0, mut x1, mut x2, x3] = *xx;

    x1 ^= (x3 << 15) ^ (x3 << 24);
    x2 ^= (x3 >> 49) ^ (x3 >> 40);

    x0 ^= (x2 << 15) ^ (x2 << 24);
    x1 ^= (x2 >> 49) ^ (x2 >> 40);

    let t = x1 >> 49;
    [x0 ^ t ^ (t << 9), x1 & M49]
}

// The unreduced product: by PCLMULQDQ where the CPU has it, which is constant time, else by
// the scalar path below.
fn impl_multiply(x: &[u64; 2], y: &[u64; 2]) -> [u64; 4] {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(proof) = Pclmulqdq::detect() {
        return x86::impl_multiply(proof, x, y);
    }
    impl_multiply_scalar(x, y)
}

// The "three-way recursion" of Bernstein's "Batch binary Edwards", on 57-bit pieces.
fn impl_multiply_scalar(x: &[u64; 2], y: &[u64; 2]) -> [u64; 4] {
    let f1 = ((x[0] >> 57) ^ (x[1] << 7)) & M57;
    let f0 = x[0] & M57;
    let g1 = ((y[0] >> 57) ^ (y[1] << 7)) & M57;
    let g0 = y[0] & M57;

    let mut u = [0; 8];
    let mut h = [0; 6];
    [h[0], h[1]] = impl_mulw(&mut u, f0, g0); // H(0)
    [h[2], h[3]] = impl_mulw(&mut u, f1, g1); // H(INF)
    [h[4], h[5]] = impl_mulw(&mut u, f0 ^ f1, g0 ^ g1); // H(1)

    let r = h[1] ^ h[2];
    let z0 = h[0];
    let z3 = h[3];
    let z1 = h[4] ^ z0 ^ r;
    let z2 = h[5] ^ z3 ^ r;

    u.zeroize();
    h.zeroize();
    [
        z0 ^ (z1 << 57),
        (z1 >> 7) ^ (z2 << 50),
        (z2 >> 14) ^ (z3 << 43),
        z3 >> 21,
    ]
}

// The product of two 57-bit words, as two 57-bit pieces, with BC's repair for the top bit of
// `y`. Variable time: the table is indexed by bits of `x`, the cache-timing side channel BC
// accepts without CLMUL.
fn impl_mulw(u: &mut [u64; 8], x: u64, y: u64) -> [u64; 2] {
    u[1] = y;
    u[2] = u[1] << 1;
    u[3] = u[2] ^ y;
    u[4] = u[2] << 1;
    u[5] = u[4] ^ y;
    u[6] = u[3] << 1;
    u[7] = u[6] ^ y;

    let mut l = u[(x & 7) as usize];
    let mut h = 0;
    for k in (3..=48).rev().step_by(9) {
        let j = x >> k;
        let g = u[(j & 7) as usize]
            ^ (u[((j >> 3) & 7) as usize] << 3)
            ^ (u[((j >> 6) & 7) as usize] << 6);
        l ^= g << k;
        h ^= g >> (64 - k);
    }
    h ^= ((x & 0x0100_8040_2010_0800) & (((y << 7) as i64 >> 63) as u64)) >> 8;

    [l & M57, (l >> 57) ^ (h << 7)]
}

// Bit i to bit 2i: by PDEP where the CPU has BMI2, else by the scalar Interleave steps.
fn impl_square(x: &[u64; 2]) -> [u64; 4] {
    let mut zz = [0; 4];
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
    use super::{impl_multiply_scalar, x86};
    use tc_runtime::intrinsics::x86::Pclmulqdq;

    #[test]
    fn the_clmul_product_is_the_scalar_one() {
        let Some(proof) = Pclmulqdq::detect() else {
            return;
        };
        let mut state = 0x0113_0113_0113_0113_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let x = [next(), next() >> 15];
            let y = [next(), next() >> 15];
            assert_eq!(
                x86::impl_multiply(proof, &x, &y),
                impl_multiply_scalar(&x, &y)
            );
        }
    }
}
