// BC's `SM2P256V1Field`: p = 2^256 - 2^224 - 2^96 + 2^64 - 1 on eight limbs.

use crate::{mod_inverse, nat};
use tc_zeroize::Zeroize;

pub(crate) const P: [u32; 8] = [
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0x0000_0000,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFE,
];

// 2^256 mod p = 2^224 + 2^96 - 2^64 + 1.
const FOLD: [i64; 8] = [1, 0, -1, 1, 0, 0, 0, 1];

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

// BC's `SM2P256V1FieldElement.Sqrt`: x^((p + 1) / 4) by its addition chain, the square root
// when there is one.
pub(crate) fn sqrt(x1: &[u32; 8]) -> [u32; 8] {
    let mut x2 = multiply(&square(x1), x1);
    let mut x4 = multiply(&square_n(&x2, 2), &x2);
    let mut x6 = multiply(&square_n(&x4, 2), &x2);
    let mut x12 = multiply(&square_n(&x6, 6), &x6);
    let mut x24 = multiply(&square_n(&x12, 12), &x12);
    let mut x30 = multiply(&square_n(&x24, 6), &x6);
    let mut x31 = multiply(&square(&x30), x1);
    let mut t1 = square_n(&x31, 31);
    let mut x62 = multiply(&t1, &x31);
    t1 = multiply(&square_n(&t1, 32), &x62);
    t1 = multiply(&square_n(&t1, 62), &x62);
    t1 = multiply(&square_n(&t1, 4), &x4);
    t1 = multiply(&square_n(&t1, 32), x1);
    t1 = square_n(&t1, 62);
    for t in [
        &mut x2, &mut x4, &mut x6, &mut x12, &mut x24, &mut x30, &mut x31, &mut x62,
    ] {
        t.zeroize();
    }
    t1
}

// BC's `Reduce`: the Solinas reduction of a product below p^2, by signed sums of its
// 32-bit words.
fn reduce(xx: &[u32; 16]) -> [u32; 8] {
    let w = |i: usize| i64::from(xx[i]);
    let (xx08, xx09, xx10, xx11) = (w(8), w(9), w(10), w(11));
    let (xx12, xx13, xx14, xx15) = (w(12), w(13), w(14), w(15));

    let t0 = xx08 + xx09;
    let t1 = xx10 + xx11;
    let t2 = xx12 + xx15;
    let t3 = xx13 + xx14;
    let t4 = t3 + (xx15 << 1);
    let ts = t0 + t3;
    let tt = t1 + t2 + ts;

    let sums = [
        w(0) + tt + xx13 + xx14 + xx15,
        w(1) + tt - xx08 + xx14 + xx15,
        w(2) - ts,
        w(3) + tt - xx09 - xx10 + xx13,
        w(4) + tt - t1 - xx08 + xx14,
        w(5) + t4 + xx10,
        w(6) + xx11 + xx14 + xx15,
        w(7) + tt + t4 + xx12,
    ];
    let mut z = [0; 8];
    let mut cc = 0i64;
    for (limb, sum) in z.iter_mut().zip(sums) {
        cc += sum;
        *limb = cc as u32;
        cc >>= 32;
    }
    debug_assert!(cc >= 0);
    nat::fold(&z, cc as u32, &FOLD, &P)
}
