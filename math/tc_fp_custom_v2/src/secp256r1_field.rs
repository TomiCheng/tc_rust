// BC's `SecP256R1Field`: p = 2^256 - 2^224 + 2^192 + 2^96 - 1 on eight limbs.

use crate::nat;
use tc_zeroize::Zeroize;

pub(crate) const P: [u32; 8] = [
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x0000_0001,
    0xFFFF_FFFF,
];

const P_MINUS_2: [u32; 8] = [
    0xFFFF_FFFD,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x0000_0001,
    0xFFFF_FFFF,
];

// (p + 1) / 4, as p = 3 mod 4.
const SQRT_EXPONENT: [u32; 8] = [
    0x0000_0000,
    0x0000_0000,
    0x4000_0000,
    0x0000_0000,
    0x0000_0000,
    0x4000_0000,
    0xC000_0000,
    0x3FFF_FFFF,
];

// 2^256 mod p = 2^224 - 2^192 - 2^96 + 1.
const FOLD: [i64; 8] = [1, 0, 0, -1, 0, 0, -1, 1];

pub(crate) fn multiply(x: &[u32; 8], y: &[u32; 8]) -> [u32; 8] {
    let mut tt = nat::mul::<8, 16>(x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u32; 8]) -> [u32; 8] {
    multiply(x, x)
}

// x^(p - 2), zero for zero.
pub(crate) fn invert(x: &[u32; 8]) -> [u32; 8] {
    nat::pow(x, &P_MINUS_2, multiply)
}

// x^((p + 1) / 4), the square root when there is one.
pub(crate) fn sqrt_candidate(x: &[u32; 8]) -> [u32; 8] {
    nat::pow(x, &SQRT_EXPONENT, multiply)
}

// BC's `Reduce`: the Solinas reduction of a product below p^2, by signed sums of its
// 32-bit words, offset by n to keep the running carry from going below zero.
fn reduce(xx: &[u32; 16]) -> [u32; 8] {
    let w = |i: usize| i64::from(xx[i]);
    const N: i64 = 6;

    let xx08 = w(8) - N;
    let (xx09, xx10, xx11, xx12) = (w(9), w(10), w(11), w(12));
    let (xx13, xx14, xx15) = (w(13), w(14), w(15));

    let t0 = xx08 + xx09;
    let t1 = xx09 + xx10;
    let t2 = xx10 + xx11 - xx15;
    let t3 = xx11 + xx12;
    let t4 = xx12 + xx13;
    let t5 = xx13 + xx14;
    let t6 = xx14 + xx15;
    let t7 = t5 - t0;

    let sums = [
        w(0) - t3 - t7,
        w(1) + t1 - t4 - t6,
        w(2) + t2 - t5,
        w(3) + (t3 << 1) + t7 - t6,
        w(4) + (t4 << 1) + xx14 - t1,
        w(5) + (t5 << 1) - t2,
        w(6) + (t6 << 1) + t7,
        w(7) + (xx15 << 1) + xx08 - t2 - t4,
    ];
    let mut z = [0; 8];
    let mut cc = 0i64;
    for (limb, sum) in z.iter_mut().zip(sums) {
        cc += sum;
        *limb = cc as u32;
        cc >>= 32;
    }
    cc += N;
    debug_assert!(cc >= 0);
    nat::fold(&z, cc as u32, &FOLD, &P)
}
