// BC's `SecP384R1Field`: p = 2^384 - 2^128 - 2^96 + 2^32 - 1 on twelve limbs.

use crate::{mod_inverse, nat};
use tc_zeroize::Zeroize;

pub(crate) const P: [u32; 12] = [
    0xFFFF_FFFF,
    0x0000_0000,
    0x0000_0000,
    0xFFFF_FFFF,
    0xFFFF_FFFE,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
];

// 2^384 mod p = 2^128 + 2^96 - 2^32 + 1.
const FOLD: [i64; 12] = [1, -1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0];

pub(crate) fn multiply(x: &[u32; 12], y: &[u32; 12]) -> [u32; 12] {
    let mut tt = nat::karatsuba_mul::<6, 12, 24>(x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u32; 12]) -> [u32; 12] {
    let mut tt = nat::karatsuba_square::<6, 12, 24>(x);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

// BC's `SquareN`: x^(2^n), for n of at least one.
pub(crate) fn square_n(x: &[u32; 12], n: usize) -> [u32; 12] {
    debug_assert!(n > 0);
    let mut z = square(x);
    for _ in 1..n {
        z = square(&z);
    }
    z
}

// BC's `Inv`, through `Mod.ModOddInverse`; zero for zero.
pub(crate) fn invert(x: &[u32; 12]) -> [u32; 12] {
    mod_inverse::mod_odd_inverse::<12, 13>(&P, x).0
}

// BC's `SecP384R1FieldElement.Sqrt`: x^((p + 1) / 4) = x^(2^382 - 2^126 - 2^94 + 2^30) by its
// addition chain, the square root when there is one.
pub(crate) fn sqrt(x1: &[u32; 12]) -> [u32; 12] {
    let mut t1 = multiply(&square(x1), x1);
    let mut t2 = multiply(&square_n(&t1, 2), &t1);
    t2 = multiply(&square(&t2), x1);
    let mut t3 = multiply(&square_n(&t2, 5), &t2);
    let mut t4 = multiply(&square_n(&t3, 5), &t2);
    t2 = multiply(&square_n(&t4, 15), &t4);
    t3 = square_n(&t2, 2);
    t1 = multiply(&t1, &t3);
    t3 = square_n(&t3, 28);
    t2 = multiply(&t2, &t3);
    t3 = multiply(&square_n(&t2, 60), &t2);
    let mut r = multiply(&square_n(&t3, 120), &t3);
    r = multiply(&square_n(&r, 15), &t4);
    r = multiply(&square_n(&r, 33), &t1);
    r = multiply(&square_n(&r, 64), x1);
    let root = square_n(&r, 30);
    for t in [&mut t1, &mut t2, &mut t3, &mut t4, &mut r] {
        t.zeroize();
    }
    root
}

// BC's `Reduce`: the Solinas reduction of a product below p^2, by signed sums of its
// 32-bit words, offset by n to keep the running carry from going below zero.
fn reduce(xx: &[u32; 24]) -> [u32; 12] {
    let w = |i: usize| i64::from(xx[i]);
    const N: i64 = 1;

    let (xx16, xx17, xx18, xx19) = (w(16), w(17), w(18), w(19));
    let (xx20, xx21, xx22, xx23) = (w(20), w(21), w(22), w(23));

    let t0 = w(12) + xx20 - N;
    let t1 = w(13) + xx22;
    let t2 = w(14) + xx22 + xx23;
    let t3 = w(15) + xx23;
    let t4 = xx17 + xx21;
    let t5 = xx21 - xx23;
    let t6 = xx22 - xx23;
    let t7 = t0 + t5;

    let sums = [
        w(0) + t7,
        w(1) + xx23 - t0 + t1,
        w(2) - xx21 - t1 + t2,
        w(3) - t2 + t3 + t7,
        w(4) + xx16 + xx21 + t1 - t3 + t7,
        w(5) - xx16 + t1 + t2 + t4,
        w(6) + xx18 - xx17 + t2 + t3,
        w(7) + xx16 + xx19 - xx18 + t3,
        w(8) + xx16 + xx17 + xx20 - xx19,
        w(9) + xx18 - xx20 + t4,
        w(10) + xx18 + xx19 - t5 + t6,
        w(11) + xx19 + xx20 - t6,
    ];
    let mut z = [0; 12];
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
