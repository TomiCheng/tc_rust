// BC's `SecT233Field`: GF(2^233) modulo x^233 + x^74 + 1, on four limbs.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;

use crate::interleave::{expand64_to128, unshuffle_pair};
#[cfg(target_arch = "x86_64")]
use tc_runtime::intrinsics::x86::Bmi2X64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use tc_runtime::intrinsics::x86::Pclmulqdq;
use tc_zeroize::Zeroize;

const M41: u64 = u64::MAX >> 23;
const M59: u64 = u64::MAX >> 5;

pub(crate) fn add(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
    [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]]
}

// x^(2^233 - 2) by BC's Itoh–Tsujii chain; zero for zero.
pub(crate) fn invert(x: &[u64; 4]) -> [u64; 4] {
    let mut t0 = multiply(&square(x), x);
    t0 = multiply(&square(&t0), x);
    let mut t1 = multiply(&square_n(&t0, 3), &t0);
    t1 = multiply(&square(&t1), x);
    t0 = multiply(&square_n(&t1, 7), &t1);
    t1 = multiply(&square_n(&t0, 14), &t0);
    t1 = multiply(&square(&t1), x);
    t0 = multiply(&square_n(&t1, 29), &t1);
    t1 = multiply(&square_n(&t0, 58), &t0);
    t0 = multiply(&square_n(&t1, 116), &t1);
    let z = square(&t0);
    t0.zeroize();
    t1.zeroize();
    z
}

// x = E(z)^2 + z·O(z)^2 for E and O made of its even and odd bits, so sqrt(x) = E + sqrt(z)·O,
// where sqrt(z) = z^32 + z^117 + z^191 times what BC folds into the odd half first.
pub(crate) fn sqrt(x: &[u64; 4]) -> [u64; 4] {
    let [mut c0, e0] = unshuffle_pair(x[0], x[1]);
    let [mut c1, e1] = unshuffle_pair(x[2], x[3]);
    let c2 = c1 >> 27;
    c1 ^= (c0 >> 27) | (c1 << 37);
    c0 ^= c0 << 37;

    let mut tt = [0; 8];
    for shift in [32, 117, 191] {
        let (w, s) = (shift >> 6, shift & 63);
        tt[w] ^= c0 << s;
        tt[w + 1] ^= (c1 << s) | (c0 >> (64 - s));
        tt[w + 2] ^= (c2 << s) | (c1 >> (64 - s));
        tt[w + 3] ^= c2 >> (64 - s);
    }
    let mut z = reduce(&tt);
    z[0] ^= e0;
    z[1] ^= e1;
    tt.zeroize();
    z
}

// x + x^4 + x^16 + ... + x^(4^116), which m = 233 being odd allows.
pub(crate) fn half_trace(x: &[u64; 4]) -> [u64; 4] {
    let mut z = *x;
    for _ in (1..233).step_by(2) {
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

// The bits of nonzero trace are 0 and 159.
pub(crate) fn trace(x: &[u64; 4]) -> u8 {
    ((x[0] ^ (x[2] >> 31)) & 1) as u8
}

fn reduce(xx: &[u64; 8]) -> [u64; 4] {
    let [mut x0, mut x1, mut x2, mut x3, mut x4, mut x5, x6, x7] = *xx;

    x3 ^= x7 << 23;
    x4 ^= (x7 >> 41) ^ (x7 << 33);
    x5 ^= x7 >> 31;

    x2 ^= x6 << 23;
    x3 ^= (x6 >> 41) ^ (x6 << 33);
    x4 ^= x6 >> 31;

    x1 ^= x5 << 23;
    x2 ^= (x5 >> 41) ^ (x5 << 33);
    x3 ^= x5 >> 31;

    x0 ^= x4 << 23;
    x1 ^= (x4 >> 41) ^ (x4 << 33);
    x2 ^= x4 >> 31;

    let t = x3 >> 41;
    [x0 ^ t, x1 ^ (t << 10), x2, x3 & M41]
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

// The "two-level seven-way recursion" of Bernstein's "Batch binary Edwards", on 59-bit
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
        x[0] & M59,
        ((x[0] >> 59) ^ (x[1] << 5)) & M59,
        ((x[1] >> 54) ^ (x[2] << 10)) & M59,
        (x[2] >> 49) ^ (x[3] << 15),
    ]
}

// Adds the product of two 59-bit words, as two 59-bit pieces, into `z[0]` and `z[1]`.
// Variable time: the table is indexed by bits of `x`, the cache-timing side channel BC
// accepts without CLMUL.
fn impl_mulw_acc(u: &mut [u64; 8], x: u64, y: u64, z: &mut [u64]) {
    debug_assert!(x >> 59 == 0);
    debug_assert!(y >> 59 == 0);

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
    debug_assert!(h >> 53 == 0);

    z[0] ^= l & M59;
    z[1] ^= (l >> 59) ^ (h << 5);
}

fn impl_compact_ext(zz: &mut [u64; 8]) {
    let [z0, z1, z2, z3, z4, z5, z6, z7] = *zz;
    *zz = [
        z0 ^ (z1 << 59),
        (z1 >> 5) ^ (z2 << 54),
        (z2 >> 10) ^ (z3 << 49),
        (z3 >> 15) ^ (z4 << 44),
        (z4 >> 20) ^ (z5 << 39),
        (z5 >> 25) ^ (z6 << 34),
        (z6 >> 30) ^ (z7 << 29),
        z7 >> 35,
    ];
}

// Bit i to bit 2i: by PDEP where the CPU has BMI2, else by the scalar Interleave steps.
fn impl_square(x: &[u64; 4]) -> [u64; 8] {
    let mut zz = [0; 8];
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
        let mut state = 0x0233_0233_0233_0233_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let x = [next(), next(), next(), next() >> 23];
            let y = [next(), next(), next(), next() >> 23];
            assert_eq!(
                x86::impl_multiply(proof, &x, &y),
                impl_multiply_scalar(&x, &y)
            );
        }
    }
}
