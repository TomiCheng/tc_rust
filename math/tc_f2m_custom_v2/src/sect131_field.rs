// BC's `SecT131Field`: GF(2^131) modulo x^131 + x^8 + x^3 + x^2 + 1, on three limbs.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;

use crate::interleave::{expand64_to128, unshuffle, unshuffle_pair};
#[cfg(target_arch = "x86_64")]
use tc_runtime::intrinsics::x86::Bmi2X64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use tc_runtime::intrinsics::x86::Pclmulqdq;
use tc_zeroize::Zeroize;

const M03: u64 = u64::MAX >> 61;
const M44: u64 = u64::MAX >> 20;
const ROOT_Z: [u64; 3] = [0x26BC_4D78_9AF1_3523, 0x26BC_4D78_9AF1_35E2, 0x6];

pub(crate) fn add(x: &[u64; 3], y: &[u64; 3]) -> [u64; 3] {
    [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2]]
}

// x^(2^131 - 2) by BC's Itoh–Tsujii chain; zero for zero.
pub(crate) fn invert(x: &[u64; 3]) -> [u64; 3] {
    let mut t0 = multiply(&square(x), x);
    let mut t1 = multiply(&square_n(&t0, 2), &t0);
    t0 = multiply(&square_n(&t1, 4), &t1);
    t1 = multiply(&square_n(&t0, 8), &t0);
    t0 = multiply(&square_n(&t1, 16), &t1);
    t1 = multiply(&square_n(&t0, 32), &t0);
    t1 = multiply(&square(&t1), x);
    t0 = multiply(&square_n(&t1, 65), &t1);
    let z = square(&t0);
    t0.zeroize();
    t1.zeroize();
    z
}

// x = E(z)^2 + z·O(z)^2 for E and O made of its even and odd bits, so sqrt(x) = E + sqrt(z)·O.
pub(crate) fn sqrt(x: &[u64; 3]) -> [u64; 3] {
    let [o0, e0] = unshuffle_pair(x[0], x[1]);
    let [o1, e1] = unshuffle(x[2]);
    let mut odd = [o0, o1, 0];
    let mut z = multiply(&odd, &ROOT_Z);
    z[0] ^= e0;
    z[1] ^= e1;
    odd.zeroize();
    z
}

// x + x^4 + x^16 + ... + x^(4^65), which m = 131 being odd allows.
pub(crate) fn half_trace(x: &[u64; 3]) -> [u64; 3] {
    let mut z = *x;
    for _ in (1..131).step_by(2) {
        z = add(&square(&square(&z)), x);
    }
    z
}

pub(crate) fn multiply(x: &[u64; 3], y: &[u64; 3]) -> [u64; 3] {
    let mut tt = impl_multiply(x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u64; 3]) -> [u64; 3] {
    let mut tt = impl_square(x);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square_n(x: &[u64; 3], n: usize) -> [u64; 3] {
    debug_assert!(n > 0);
    let mut z = square(x);
    for _ in 1..n {
        z = square(&z);
    }
    z
}

// The bits of nonzero trace are 0, 123 and 129.
pub(crate) fn trace(x: &[u64; 3]) -> u8 {
    ((x[0] ^ (x[1] >> 59) ^ (x[2] >> 1)) & 1) as u8
}

// The product's sixth limb is always zero and is not read.
fn reduce(xx: &[u64; 6]) -> [u64; 3] {
    let [mut x0, mut x1, mut x2, mut x3, x4, _] = *xx;

    x1 ^= (x4 << 61) ^ (x4 << 63);
    x2 ^= (x4 >> 3) ^ (x4 >> 1) ^ x4 ^ (x4 << 5);
    x3 ^= x4 >> 59;

    x0 ^= (x3 << 61) ^ (x3 << 63);
    x1 ^= (x3 >> 3) ^ (x3 >> 1) ^ x3 ^ (x3 << 5);
    x2 ^= x3 >> 59;

    let t = x2 >> 3;
    [
        x0 ^ t ^ (t << 2) ^ (t << 3) ^ (t << 8),
        x1 ^ (t >> 56),
        x2 & M03,
    ]
}

// The unreduced product: by PCLMULQDQ where the CPU has it, which is constant time, else by
// the scalar path below.
fn impl_multiply(x: &[u64; 3], y: &[u64; 3]) -> [u64; 6] {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(proof) = Pclmulqdq::detect() {
        return x86::impl_multiply(proof, x, y);
    }
    impl_multiply_scalar(x, y)
}

// The "five-way recursion" of Bernstein's "Batch binary Edwards", on 44-bit pieces.
fn impl_multiply_scalar(x: &[u64; 3], y: &[u64; 3]) -> [u64; 6] {
    let f2 = ((x[1] >> 24) ^ (x[2] << 40)) & M44;
    let f1 = ((x[0] >> 44) ^ (x[1] << 20)) & M44;
    let f0 = x[0] & M44;

    let g2 = ((y[1] >> 24) ^ (y[2] << 40)) & M44;
    let g1 = ((y[0] >> 44) ^ (y[1] << 20)) & M44;
    let g0 = y[0] & M44;

    let mut u = [0; 8];
    let mut h = [0; 10];
    [h[0], h[1]] = impl_mulw(&mut u, f0, g0); // H(0)
    [h[2], h[3]] = impl_mulw(&mut u, f2, g2); // H(INF)

    let t0 = f0 ^ f1 ^ f2;
    let t1 = g0 ^ g1 ^ g2;
    [h[4], h[5]] = impl_mulw(&mut u, t0, t1); // H(1)

    let t2 = (f1 << 1) ^ (f2 << 2);
    let t3 = (g1 << 1) ^ (g2 << 2);
    [h[6], h[7]] = impl_mulw(&mut u, f0 ^ t2, g0 ^ t3); // H(t)
    [h[8], h[9]] = impl_mulw(&mut u, t0 ^ t2, t1 ^ t3); // H(t + 1)

    let t4 = h[6] ^ h[8];
    let t5 = h[7] ^ h[9];

    let v0 = (t4 << 1) ^ h[6];
    let v1 = t4 ^ (t5 << 1) ^ h[7];
    let v2 = t5;

    let u0 = h[0];
    let u1 = h[1] ^ h[0] ^ h[4];
    let u2 = h[1] ^ h[5];

    let mut w0 = u0 ^ v0 ^ (h[2] << 4) ^ (h[2] << 1);
    let mut w1 = u1 ^ v1 ^ (h[3] << 4) ^ (h[3] << 1);
    let mut w2 = u2 ^ v2;

    w1 ^= w0 >> 44;
    w0 &= M44;
    w2 ^= w1 >> 44;
    w1 &= M44;

    // W / t
    w0 = (w0 >> 1) ^ ((w1 & 1) << 43);
    w1 = (w1 >> 1) ^ ((w2 & 1) << 43);
    w2 >>= 1;

    // W / (t + 1)
    w0 = prefix_xor(w0) & M44;
    w1 ^= w0 >> 43;
    w1 = prefix_xor(w1) & M44;
    w2 ^= w1 >> 43;
    w2 = prefix_xor(w2);

    let mut zz = [
        u0,
        u1 ^ w0 ^ h[2],
        u2 ^ w1 ^ w0 ^ h[3],
        w2 ^ w1,
        w2 ^ h[2],
        h[3],
    ];
    impl_compact_ext(&mut zz);

    u.zeroize();
    h.zeroize();
    zz
}

// Each bit becomes the XOR of itself and every bit below it.
fn prefix_xor(mut w: u64) -> u64 {
    w ^= w << 1;
    w ^= w << 2;
    w ^= w << 4;
    w ^= w << 8;
    w ^= w << 16;
    w ^= w << 32;
    w
}

// The product of two 44-bit words, as two 44-bit pieces. Variable time: the table is indexed
// by bits of `x`, the cache-timing side channel BC accepts without CLMUL.
fn impl_mulw(u: &mut [u64; 8], x: u64, y: u64) -> [u64; 2] {
    u[1] = y;
    u[2] = u[1] << 1;
    u[3] = u[2] ^ y;
    u[4] = u[2] << 1;
    u[5] = u[4] ^ y;
    u[6] = u[3] << 1;
    u[7] = u[6] ^ y;

    let window = |j: u64| {
        u[(j & 7) as usize]
            ^ (u[((j >> 3) & 7) as usize] << 3)
            ^ (u[((j >> 6) & 7) as usize] << 6)
            ^ (u[((j >> 9) & 7) as usize] << 9)
            ^ (u[((j >> 12) & 7) as usize] << 12)
    };
    let mut l = window(x);
    let mut h = 0;
    for k in [30, 15] {
        let g = window(x >> k);
        l ^= g << k;
        h ^= g >> (64 - k);
    }

    [l & M44, (l >> 44) ^ (h << 20)]
}

fn impl_compact_ext(zz: &mut [u64; 6]) {
    let [z0, z1, z2, z3, z4, z5] = *zz;
    *zz = [
        z0 ^ (z1 << 44),
        (z1 >> 20) ^ (z2 << 24),
        (z2 >> 40) ^ (z3 << 4) ^ (z4 << 48),
        (z3 >> 60) ^ (z5 << 28) ^ (z4 >> 16),
        z5 >> 36,
        0,
    ];
}

// Bit i to bit 2i: by PDEP where the CPU has BMI2, else by the scalar Interleave steps. The
// top limb holds three bits, so its low half suffices.
fn impl_square(x: &[u64; 3]) -> [u64; 6] {
    let mut zz = [0; 6];
    zz[4] = expand64_to128(x[2])[0];
    #[cfg(target_arch = "x86_64")]
    if let Some(proof) = Bmi2X64::detect() {
        crate::interleave::x86::expand(proof, &x[..2], &mut zz[..4]);
        return zz;
    }
    for i in 0..2 {
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
        let mut state = 0x0131_0131_0131_0131_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let x = [next(), next(), next() >> 61];
            let y = [next(), next(), next() >> 61];
            assert_eq!(
                x86::impl_multiply(proof, &x, &y),
                impl_multiply_scalar(&x, &y)
            );
        }
    }
}
