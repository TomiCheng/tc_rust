// BC's `SecT163Field`: GF(2^163) modulo x^163 + x^7 + x^6 + x^3 + 1, on three limbs.

use crate::interleave::expand64_to128;
use tc_zeroize::Zeroize;

const M35: u64 = u64::MAX >> 29;
const M55: u64 = u64::MAX >> 9;

pub(crate) fn add(x: &[u64; 3], y: &[u64; 3]) -> [u64; 3] {
    [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2]]
}

pub(crate) fn multiply(x: &[u64; 3], y: &[u64; 3]) -> [u64; 3] {
    let mut tt = [0; 6];
    impl_multiply(x, y, &mut tt);
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

// The bits of nonzero trace are 0 and 157.
pub(crate) fn trace(x: &[u64; 3]) -> u8 {
    ((x[0] ^ (x[2] >> 29)) & 1) as u8
}

fn reduce(xx: &[u64; 6]) -> [u64; 3] {
    let [mut x0, mut x1, mut x2, x3, x4, x5] = *xx;

    x2 ^= (x5 << 29) ^ (x5 << 32) ^ (x5 << 35) ^ (x5 << 36);
    let x3 = x3 ^ (x5 >> 35) ^ (x5 >> 32) ^ (x5 >> 29) ^ (x5 >> 28);

    x1 ^= (x4 << 29) ^ (x4 << 32) ^ (x4 << 35) ^ (x4 << 36);
    x2 ^= (x4 >> 35) ^ (x4 >> 32) ^ (x4 >> 29) ^ (x4 >> 28);

    x0 ^= (x3 << 29) ^ (x3 << 32) ^ (x3 << 35) ^ (x3 << 36);
    x1 ^= (x3 >> 35) ^ (x3 >> 32) ^ (x3 >> 29) ^ (x3 >> 28);

    let t = x2 >> 35;
    [x0 ^ t ^ (t << 3) ^ (t << 6) ^ (t << 7), x1, x2 & M35]
}

// The "five-way recursion" of Bernstein's "Batch binary Edwards", on 55-bit pieces.
fn impl_multiply(x: &[u64; 3], y: &[u64; 3], zz: &mut [u64; 6]) {
    let f2 = (x[1] >> 46) ^ (x[2] << 18);
    let f1 = ((x[0] >> 55) ^ (x[1] << 9)) & M55;
    let f0 = x[0] & M55;

    let g2 = (y[1] >> 46) ^ (y[2] << 18);
    let g1 = ((y[0] >> 55) ^ (y[1] << 9)) & M55;
    let g0 = y[0] & M55;

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
    debug_assert!(t5 >> 55 == 0);

    let v0 = (t4 << 1) ^ h[6];
    let v1 = t4 ^ (t5 << 1) ^ h[7];
    let v2 = t5;

    let u0 = h[0];
    let u1 = h[1] ^ h[0] ^ h[4];
    let u2 = h[1] ^ h[5];

    let mut w0 = u0 ^ v0 ^ (h[2] << 4) ^ (h[2] << 1);
    let mut w1 = u1 ^ v1 ^ (h[3] << 4) ^ (h[3] << 1);
    let mut w2 = u2 ^ v2;

    w1 ^= w0 >> 55;
    w0 &= M55;
    w2 ^= w1 >> 55;
    w1 &= M55;
    debug_assert!(w0 & 1 == 0);

    // W / t
    w0 = (w0 >> 1) ^ ((w1 & 1) << 54);
    w1 = (w1 >> 1) ^ ((w2 & 1) << 54);
    w2 >>= 1;

    // W / (t + 1)
    w0 = prefix_xor(w0) & M55;
    w1 ^= w0 >> 54;
    w1 = prefix_xor(w1) & M55;
    w2 ^= w1 >> 54;
    w2 = prefix_xor(w2);
    debug_assert!(w2 >> 52 == 0);

    *zz = [
        u0,
        u1 ^ w0 ^ h[2],
        u2 ^ w1 ^ w0 ^ h[3],
        w2 ^ w1,
        w2 ^ h[2],
        h[3],
    ];
    impl_compact_ext(zz);

    u.zeroize();
    h.zeroize();
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

// The product of two 56-bit words, as two 55-bit pieces. Variable time: the table is
// indexed by bits of `x`, the cache-timing side channel BC accepts without CLMUL.
fn impl_mulw(u: &mut [u64; 8], x: u64, y: u64) -> [u64; 2] {
    debug_assert!(x >> 56 == 0);
    debug_assert!(y >> 56 == 0);

    u[1] = y;
    u[2] = u[1] << 1;
    u[3] = u[2] ^ y;
    u[4] = u[2] << 1;
    u[5] = u[4] ^ y;
    u[6] = u[3] << 1;
    u[7] = u[6] ^ y;

    let mut l = u[(x & 3) as usize];
    let mut h = 0;
    for k in (2..=47).rev().step_by(9) {
        let j = x >> k;
        let g = u[(j & 7) as usize]
            ^ (u[((j >> 3) & 7) as usize] << 3)
            ^ (u[((j >> 6) & 7) as usize] << 6);
        l ^= g << k;
        h ^= g >> (64 - k);
    }
    debug_assert!(h >> 47 == 0);

    [l & M55, (l >> 55) ^ (h << 9)]
}

fn impl_compact_ext(zz: &mut [u64; 6]) {
    let [z0, z1, z2, z3, z4, z5] = *zz;
    *zz = [
        z0 ^ (z1 << 55),
        (z1 >> 9) ^ (z2 << 46),
        (z2 >> 18) ^ (z3 << 37),
        (z3 >> 27) ^ (z4 << 28),
        (z4 >> 36) ^ (z5 << 19),
        z5 >> 45,
    ];
}

fn impl_square(x: &[u64; 3]) -> [u64; 6] {
    let [z0, z1] = expand64_to128(x[0]);
    let [z2, z3] = expand64_to128(x[1]);
    let [z4, z5] = expand64_to128(x[2]);
    [z0, z1, z2, z3, z4, z5]
}
