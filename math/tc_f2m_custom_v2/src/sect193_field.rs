// BC's `SecT193Field`: GF(2^193) modulo x^193 + x^15 + 1, on four limbs.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;

use crate::interleave::{expand64_to128, unshuffle, unshuffle_pair};
#[cfg(target_arch = "x86_64")]
use tc_runtime::intrinsics::x86::Bmi2X64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use tc_runtime::intrinsics::x86::Pclmulqdq;
use tc_zeroize::Zeroize;

const M01: u64 = 1;
const M49: u64 = u64::MAX >> 15;

pub(crate) fn add(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
    [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]]
}

// x^(2^193 - 2) by Itoh–Tsujii, on the bases { 2, 3 } of 192 = 3·2^6; zero for zero.
pub(crate) fn invert(x: &[u64; 4]) -> [u64; 4] {
    let mut t0 = square(x);
    // 3 | 192
    let mut t1 = square_n(&t0, 1);
    t0 = multiply(&t0, &t1);
    t1 = square_n(&t1, 1);
    t0 = multiply(&t0, &t1);
    // 2 | 64, 32, 16, 8, 4
    for n in [3, 6, 12, 24, 48] {
        t1 = square_n(&t0, n);
        t0 = multiply(&t0, &t1);
    }
    // 2 | 2
    t1 = square_n(&t0, 96);
    let z = multiply(&t0, &t1);
    t0.zeroize();
    t1.zeroize();
    z
}

// x = E(z)^2 + z·O(z)^2 for E and O made of its even and odd bits, so sqrt(x) = E + sqrt(z)·O,
// where sqrt(z) = z^8 + z^33.
pub(crate) fn sqrt(x: &[u64; 4]) -> [u64; 4] {
    let [c0, e0] = unshuffle_pair(x[0], x[1]);
    let [c1, mut e1] = unshuffle(x[2]);
    e1 ^= x[3] << 32;
    [
        e0 ^ (c0 << 8),
        e1 ^ (c1 << 8) ^ (c0 >> 56) ^ (c0 << 33),
        (c1 >> 56) ^ (c1 << 33) ^ (c0 >> 31),
        c1 >> 31,
    ]
}

// x + x^4 + x^16 + ... + x^(4^96), which m = 193 being odd allows.
pub(crate) fn half_trace(x: &[u64; 4]) -> [u64; 4] {
    let mut z = *x;
    for _ in (1..193).step_by(2) {
        z = add(&square(&square(&z)), x);
    }
    z
}

pub(crate) fn multiply(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
    let mut tt = impl_multiply(x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u64; 4]) -> [u64; 4] {
    let mut tt = impl_square(x);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square_n(x: &[u64; 4], n: usize) -> [u64; 4] {
    debug_assert!(n > 0);
    let mut z = square(x);
    for _ in 1..n {
        z = square(&z);
    }
    z
}

// The only bit of nonzero trace is 0.
pub(crate) fn trace(x: &[u64; 4]) -> u8 {
    (x[0] & 1) as u8
}

// The product's eighth limb is always zero and is not read.
fn reduce(xx: &[u64; 8]) -> [u64; 4] {
    let [mut x0, mut x1, mut x2, mut x3, mut x4, x5, x6, _] = *xx;

    x2 ^= x6 << 63;
    x3 ^= (x6 >> 1) ^ (x6 << 14);
    x4 ^= x6 >> 50;

    x1 ^= x5 << 63;
    x2 ^= (x5 >> 1) ^ (x5 << 14);
    x3 ^= x5 >> 50;

    x0 ^= x4 << 63;
    x1 ^= (x4 >> 1) ^ (x4 << 14);
    x2 ^= x4 >> 50;

    let t = x3 >> 1;
    [x0 ^ t ^ (t << 15), x1 ^ (t >> 49), x2, x3 & M01]
}

// The unreduced product: by PCLMULQDQ where the CPU has it, which is constant time, else by
// the scalar path below.
fn impl_multiply(x: &[u64; 4], y: &[u64; 4]) -> [u64; 8] {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(proof) = Pclmulqdq::detect() {
        return x86::impl_multiply(proof, x, y);
    }
    impl_multiply_scalar(x, y)
}

// The "two-level seven-way recursion" of Bernstein's "Batch binary Edwards", on 49-bit
// pieces.
fn impl_multiply_scalar(x: &[u64; 4], y: &[u64; 4]) -> [u64; 8] {
    let (mut f, mut g) = (impl_expand(x), impl_expand(y));
    let mut u = [0; 8];
    let mut zz = [0; 8];

    for i in 0..4 {
        impl_mulw_acc(&mut u, f[i], g[i], &mut zz[i..]);
    }
    // U *= (1 - t^n)
    for i in (1..=5).rev() {
        zz[i] ^= zz[i - 1];
    }
    impl_mulw_acc(&mut u, f[0] ^ f[1], g[0] ^ g[1], &mut zz[1..]);
    impl_mulw_acc(&mut u, f[2] ^ f[3], g[2] ^ g[3], &mut zz[3..]);
    // V *= (1 - t^2n)
    for i in (2..=7).rev() {
        zz[i] ^= zz[i - 2];
    }
    // The double-length recursion.
    let (c0, c1) = (f[0] ^ f[2], f[1] ^ f[3]);
    let (d0, d1) = (g[0] ^ g[2], g[1] ^ g[3]);
    impl_mulw_acc(&mut u, c0 ^ c1, d0 ^ d1, &mut zz[3..]);
    let mut t = [0; 3];
    impl_mulw_acc(&mut u, c0, d0, &mut t[0..]);
    impl_mulw_acc(&mut u, c1, d1, &mut t[1..]);
    zz[2] ^= t[0];
    zz[3] ^= t[0] ^ t[1];
    zz[4] ^= t[2] ^ t[1];
    zz[5] ^= t[2];
    impl_compact_ext(&mut zz);

    f.zeroize();
    g.zeroize();
    u.zeroize();
    t.zeroize();
    zz
}

fn impl_expand(x: &[u64; 4]) -> [u64; 4] {
    [
        x[0] & M49,
        ((x[0] >> 49) ^ (x[1] << 15)) & M49,
        ((x[1] >> 34) ^ (x[2] << 30)) & M49,
        (x[2] >> 19) ^ (x[3] << 45),
    ]
}

// Adds the product of two 49-bit words, as two 49-bit pieces, into `z[0]` and `z[1]`.
// Variable time: the table is indexed by bits of `x`, the cache-timing side channel BC
// accepts without CLMUL.
fn impl_mulw_acc(u: &mut [u64; 8], x: u64, y: u64, z: &mut [u64]) {
    u[1] = y;
    u[2] = u[1] << 1;
    u[3] = u[2] ^ y;
    u[4] = u[2] << 1;
    u[5] = u[4] ^ y;
    u[6] = u[3] << 1;
    u[7] = u[6] ^ y;

    let mut l = u[(x & 7) as usize] ^ (u[((x >> 3) & 7) as usize] << 3);
    let mut h = 0;
    for k in [36, 21, 6] {
        let j = x >> k;
        let g = u[(j & 7) as usize]
            ^ (u[((j >> 3) & 7) as usize] << 3)
            ^ (u[((j >> 6) & 7) as usize] << 6)
            ^ (u[((j >> 9) & 7) as usize] << 9)
            ^ (u[((j >> 12) & 7) as usize] << 12);
        l ^= g << k;
        h ^= g >> (64 - k);
    }

    z[0] ^= l & M49;
    z[1] ^= (l >> 49) ^ (h << 15);
}

fn impl_compact_ext(zz: &mut [u64; 8]) {
    let [z0, z1, z2, z3, z4, z5, z6, z7] = *zz;
    *zz = [
        z0 ^ (z1 << 49),
        (z1 >> 15) ^ (z2 << 34),
        (z2 >> 30) ^ (z3 << 19),
        (z3 >> 45) ^ (z4 << 4) ^ (z5 << 53),
        (z4 >> 60) ^ (z6 << 38) ^ (z5 >> 11),
        (z6 >> 26) ^ (z7 << 23),
        z7 >> 41,
        0,
    ];
}

// Bit i to bit 2i: by PDEP where the CPU has BMI2, else by the scalar Interleave steps. The
// top limb holds one bit, which lands at bit 384.
fn impl_square(x: &[u64; 4]) -> [u64; 8] {
    let mut zz = [0; 8];
    zz[6] = x[3] & M01;
    #[cfg(target_arch = "x86_64")]
    if let Some(proof) = Bmi2X64::detect() {
        crate::interleave::x86::expand(proof, &x[..3], &mut zz[..6]);
        return zz;
    }
    for i in 0..3 {
        [zz[2 * i], zz[2 * i + 1]] = expand64_to128(x[i]);
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
        let mut state = 0x0193_0193_0193_0193_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let x = [next(), next(), next(), next() >> 63];
            let y = [next(), next(), next(), next() >> 63];
            assert_eq!(
                x86::impl_multiply(proof, &x, &y),
                impl_multiply_scalar(&x, &y)
            );
        }
    }
}
