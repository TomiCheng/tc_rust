// BC's `SecP256R1Field`: p = 2^256 - 2^224 + 2^192 + 2^96 - 1 on eight limbs.

use crate::{mod_inverse, nat};
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

// 2^256 mod p = 2^224 - 2^192 - 2^96 + 1.
const FOLD: [i64; 8] = [1, 0, 0, -1, 0, 0, -1, 1];

pub(crate) fn multiply(x: &[u32; 8], y: &[u32; 8]) -> [u32; 8] {
    let mut tt = nat::mul::<8, 16>(x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u32; 8]) -> [u32; 8] {
    let mut tt = nat::square::<8, 16>(x);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

// BC's `SquareN`: x^(2^n), for n of at least one.
pub(crate) fn square_n(x: &[u32; 8], n: usize) -> [u32; 8] {
    debug_assert!(n > 0);
    let mut tt = nat::square::<8, 16>(x);
    let mut z = reduce(&tt);
    for _ in 1..n {
        tt = nat::square::<8, 16>(&z);
        z = reduce(&tt);
    }
    tt.zeroize();
    z
}

// BC's `Inv`, through `Mod.ModOddInverse`; zero for zero.
pub(crate) fn invert(x: &[u32; 8]) -> [u32; 8] {
    mod_inverse::mod_odd_inverse::<8, 9>(&P, x).0
}

// BC's `SecP256R1FieldElement.Sqrt`: x^((p + 1) / 4) = x^(2^254 - 2^222 + 2^190 + 2^94) by
// its addition chain, the square root when there is one.
pub(crate) fn sqrt(x1: &[u32; 8]) -> [u32; 8] {
    let mut t1 = multiply(&square(x1), x1);
    let mut t2 = multiply(&square_n(&t1, 2), &t1);
    t1 = multiply(&square_n(&t2, 4), &t2);
    t2 = multiply(&square_n(&t1, 8), &t1);
    t1 = multiply(&square_n(&t2, 16), &t2);
    t1 = multiply(&square_n(&t1, 32), x1);
    t1 = multiply(&square_n(&t1, 96), x1);
    t1 = square_n(&t1, 94);
    t2.zeroize();
    t1
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
