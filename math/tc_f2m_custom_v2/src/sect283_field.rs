// BC's `SecT283Field`: GF(2^283) modulo x^283 + x^12 + x^7 + x^5 + 1, on five limbs.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;

use crate::interleave::{expand64_to128, unshuffle, unshuffle_pair};
#[cfg(target_arch = "x86_64")]
use tc_runtime::intrinsics::x86::Bmi2X64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use tc_runtime::intrinsics::x86::Pclmulqdq;
use tc_zeroize::Zeroize;

const M27: u64 = u64::MAX >> 37;
const M57: u64 = u64::MAX >> 7;
const ROOT_Z: [u64; 5] = [
    0x0C30_C30C_30C3_0808,
    0x30C3_0C30_C30C_30C3,
    0x8208_2082_0820_830C,
    0x0820_8208_2082_0820,
    0x0208_2082,
];

pub(crate) fn add(x: &[u64; 5], y: &[u64; 5]) -> [u64; 5] {
    [
        x[0] ^ y[0],
        x[1] ^ y[1],
        x[2] ^ y[2],
        x[3] ^ y[3],
        x[4] ^ y[4],
    ]
}

// x^(2^283 - 2) by BC's Itoh–Tsujii chain; zero for zero.
pub(crate) fn invert(x: &[u64; 5]) -> [u64; 5] {
    let mut t0 = multiply(&square(x), x);
    let mut t1 = multiply(&square_n(&t0, 2), &t0);
    t0 = multiply(&square_n(&t1, 4), &t1);
    t1 = multiply(&square_n(&t0, 8), &t0);
    t1 = multiply(&square(&t1), x);
    t0 = multiply(&square_n(&t1, 17), &t1);
    t0 = multiply(&square(&t0), x);
    t1 = multiply(&square_n(&t0, 35), &t0);
    t0 = multiply(&square_n(&t1, 70), &t1);
    t0 = multiply(&square(&t0), x);
    t1 = multiply(&square_n(&t0, 141), &t0);
    let z = square(&t1);
    t0.zeroize();
    t1.zeroize();
    z
}

// x = E(z)^2 + z·O(z)^2 for E and O made of its even and odd bits, so sqrt(x) = E + sqrt(z)·O.
pub(crate) fn sqrt(x: &[u64; 5]) -> [u64; 5] {
    let [o0, e0] = unshuffle_pair(x[0], x[1]);
    let [o1, e1] = unshuffle_pair(x[2], x[3]);
    let [o2, e2] = unshuffle(x[4]);
    let mut odd = [o0, o1, o2, 0, 0];
    let mut z = multiply(&odd, &ROOT_Z);
    z[0] ^= e0;
    z[1] ^= e1;
    z[2] ^= e2;
    odd.zeroize();
    z
}

// x + x^4 + x^16 + ... + x^(4^141), which m = 283 being odd allows.
pub(crate) fn half_trace(x: &[u64; 5]) -> [u64; 5] {
    let mut z = *x;
    for _ in (1..283).step_by(2) {
        z = add(&square(&square(&z)), x);
    }
    z
}

pub(crate) fn multiply(x: &[u64; 5], y: &[u64; 5]) -> [u64; 5] {
    let mut tt = impl_multiply(x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u64; 5]) -> [u64; 5] {
    let mut tt = impl_square(x);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square_n(x: &[u64; 5], n: usize) -> [u64; 5] {
    debug_assert!(n > 0);
    let mut z = square(x);
    for _ in 1..n {
        z = square(&z);
    }
    z
}

// The bits of nonzero trace are 0 and 271.
pub(crate) fn trace(x: &[u64; 5]) -> u8 {
    ((x[0] ^ (x[4] >> 15)) & 1) as u8
}

// The product's tenth limb is always zero and is not read.
fn reduce(xx: &[u64; 10]) -> [u64; 5] {
    let [mut x0, mut x1, mut x2, mut x3, mut x4, x5, x6, x7, x8, _] = *xx;

    x3 ^= (x8 << 37) ^ (x8 << 42) ^ (x8 << 44) ^ (x8 << 49);
    x4 ^= (x8 >> 27) ^ (x8 >> 22) ^ (x8 >> 20) ^ (x8 >> 15);

    x2 ^= (x7 << 37) ^ (x7 << 42) ^ (x7 << 44) ^ (x7 << 49);
    x3 ^= (x7 >> 27) ^ (x7 >> 22) ^ (x7 >> 20) ^ (x7 >> 15);

    x1 ^= (x6 << 37) ^ (x6 << 42) ^ (x6 << 44) ^ (x6 << 49);
    x2 ^= (x6 >> 27) ^ (x6 >> 22) ^ (x6 >> 20) ^ (x6 >> 15);

    x0 ^= (x5 << 37) ^ (x5 << 42) ^ (x5 << 44) ^ (x5 << 49);
    x1 ^= (x5 >> 27) ^ (x5 >> 22) ^ (x5 >> 20) ^ (x5 >> 15);

    let t = x4 >> 27;
    [
        x0 ^ t ^ (t << 5) ^ (t << 7) ^ (t << 12),
        x1,
        x2,
        x3,
        x4 & M27,
    ]
}

// The unreduced product: by PCLMULQDQ where the CPU has it, which is constant time, else by
// the scalar path below.
fn impl_multiply(x: &[u64; 5], y: &[u64; 5]) -> [u64; 10] {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(proof) = Pclmulqdq::detect() {
        return x86::impl_multiply(proof, x, y);
    }
    impl_multiply_scalar(x, y)
}

// Formula (17) of Cenk and Hasan's "Some New Results on Binary Polynomial Multiplication",
// on 57-bit pieces, with BC's correction of its term t25.
fn impl_multiply_scalar(x: &[u64; 5], y: &[u64; 5]) -> [u64; 10] {
    let (mut a, mut b) = (impl_expand(x), impl_expand(y));
    let mut u = [0; 8];
    let mut p = [0; 26];

    for i in 0..5 {
        [p[2 * i], p[2 * i + 1]] = impl_mulw(&mut u, a[i], b[i]); // m1 to m5
    }

    let (u0, v0) = (a[0] ^ a[1], b[0] ^ b[1]);
    let (u1, v1) = (a[0] ^ a[2], b[0] ^ b[2]);
    let (u2, v2) = (a[2] ^ a[4], b[2] ^ b[4]);
    let (u3, v3) = (a[3] ^ a[4], b[3] ^ b[4]);

    [p[18], p[19]] = impl_mulw(&mut u, u1 ^ a[3], v1 ^ b[3]); // m10
    [p[20], p[21]] = impl_mulw(&mut u, u2 ^ a[1], v2 ^ b[1]); // m11

    let (a4, b4) = (u0 ^ u3, v0 ^ v3);
    let (a5, b5) = (a4 ^ a[2], b4 ^ b[2]);

    [p[22], p[23]] = impl_mulw(&mut u, a4, b4); // m12
    [p[24], p[25]] = impl_mulw(&mut u, a5, b5); // m13

    [p[10], p[11]] = impl_mulw(&mut u, u0, v0); // m6
    [p[12], p[13]] = impl_mulw(&mut u, u1, v1); // m7
    [p[14], p[15]] = impl_mulw(&mut u, u2, v2); // m8
    [p[16], p[17]] = impl_mulw(&mut u, u3, v3); // m9

    // p1 to p26 of the paper are p[0] to p[25] here.
    let mut zz = [0; 10];
    zz[0] = p[0];
    zz[9] = p[9];
    let t1 = p[0] ^ p[1];
    let t2 = t1 ^ p[2];
    let t3 = t2 ^ p[10];
    zz[1] = t3;
    let t4 = p[3] ^ p[4];
    let t5 = p[11] ^ p[12];
    let t6 = t4 ^ t5;
    let t7 = t2 ^ t6;
    zz[2] = t7;
    let t8 = t1 ^ t4;
    let t9 = p[5] ^ p[6];
    let t10 = t8 ^ t9;
    let t11 = t10 ^ p[8];
    let t12 = p[13] ^ p[14];
    let t13 = t11 ^ t12;
    let t14 = p[18] ^ p[22];
    let t15 = t14 ^ p[24];
    let t16 = t13 ^ t15;
    zz[3] = t16;
    let t17 = p[7] ^ p[8];
    let t18 = t17 ^ p[9];
    let t19 = t18 ^ p[17];
    zz[8] = t19;
    let t20 = t18 ^ t9;
    let t21 = p[15] ^ p[16];
    let t22 = t20 ^ t21;
    zz[7] = t22;
    let t23 = t22 ^ t3;
    let t24 = p[19] ^ p[20];
    // The paper has p[23] here; BC corrects it to p[25].
    let t25 = p[25] ^ p[24];
    let t26 = p[18] ^ p[23];
    let t27 = t24 ^ t25;
    let t28 = t27 ^ t26;
    let t29 = t28 ^ t23;
    zz[4] = t29;
    let t30 = t7 ^ t19;
    let t31 = t27 ^ t30;
    let t32 = p[21] ^ p[22];
    let t33 = t31 ^ t32;
    zz[5] = t33;
    let t34 = t11 ^ p[0];
    let t35 = t34 ^ p[9];
    let t36 = t35 ^ t12;
    let t37 = t36 ^ p[21];
    let t38 = t37 ^ p[23];
    let t39 = t38 ^ p[25];
    zz[6] = t39;
    impl_compact_ext(&mut zz);

    a.zeroize();
    b.zeroize();
    u.zeroize();
    p.zeroize();
    zz
}

fn impl_expand(x: &[u64; 5]) -> [u64; 5] {
    [
        x[0] & M57,
        ((x[0] >> 57) ^ (x[1] << 7)) & M57,
        ((x[1] >> 50) ^ (x[2] << 14)) & M57,
        ((x[2] >> 43) ^ (x[3] << 21)) & M57,
        (x[3] >> 36) ^ (x[4] << 28),
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

fn impl_compact_ext(zz: &mut [u64; 10]) {
    let [z0, z1, z2, z3, z4, z5, z6, z7, z8, z9] = *zz;
    *zz = [
        z0 ^ (z1 << 57),
        (z1 >> 7) ^ (z2 << 50),
        (z2 >> 14) ^ (z3 << 43),
        (z3 >> 21) ^ (z4 << 36),
        (z4 >> 28) ^ (z5 << 29),
        (z5 >> 35) ^ (z6 << 22),
        (z6 >> 42) ^ (z7 << 15),
        (z7 >> 49) ^ (z8 << 8),
        (z8 >> 56) ^ (z9 << 1),
        z9 >> 63,
    ];
}

// Bit i to bit 2i: by PDEP where the CPU has BMI2, else by the scalar Interleave steps. The
// top limb holds 27 bits, so its low half suffices.
fn impl_square(x: &[u64; 5]) -> [u64; 10] {
    let mut zz = [0; 10];
    zz[8] = expand64_to128(x[4])[0];
    #[cfg(target_arch = "x86_64")]
    if let Some(proof) = Bmi2X64::detect() {
        crate::interleave::x86::expand(proof, &x[..4], &mut zz[..8]);
        return zz;
    }
    for i in 0..4 {
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
        let mut state = 0x0283_0283_0283_0283_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let x = [next(), next(), next(), next(), next() >> 37];
            let y = [next(), next(), next(), next(), next() >> 37];
            assert_eq!(
                x86::impl_multiply(proof, &x, &y),
                impl_multiply_scalar(&x, &y)
            );
        }
    }
}
