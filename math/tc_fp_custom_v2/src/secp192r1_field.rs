// BC's `SecP192R1Field`: p = 2^192 - 2^64 - 1 on six limbs.

use crate::{mod_inverse, nat};
use tc_zeroize::Zeroize;

pub(crate) const P: [u32; 6] = [
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFE,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
];

pub(crate) fn multiply(x: &[u32; 6], y: &[u32; 6]) -> [u32; 6] {
    let mut tt = nat::mul::<6, 12>(x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u32; 6]) -> [u32; 6] {
    let mut tt = nat::square::<6, 12>(x);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

// BC's `SquareN`: x^(2^n), for n of at least one.
pub(crate) fn square_n(x: &[u32; 6], n: usize) -> [u32; 6] {
    debug_assert!(n > 0);
    let mut tt = nat::square::<6, 12>(x);
    let mut z = reduce(&tt);
    for _ in 1..n {
        tt = nat::square::<6, 12>(&z);
        z = reduce(&tt);
    }
    tt.zeroize();
    z
}

// BC's `Inv`, through `Mod.ModOddInverse`; zero for zero.
pub(crate) fn invert(x: &[u32; 6]) -> [u32; 6] {
    mod_inverse::mod_odd_inverse::<6, 7>(&P, x).0
}

// BC's `SecP192R1FieldElement.Sqrt`: x^((p + 1) / 4) = x^(2^190 - 2^62) by its addition
// chain, the square root when there is one.
pub(crate) fn sqrt(x1: &[u32; 6]) -> [u32; 6] {
    let mut t1 = multiply(&square(x1), x1);
    let mut t2 = multiply(&square_n(&t1, 2), &t1);
    t1 = multiply(&square_n(&t2, 4), &t2);
    t2 = multiply(&square_n(&t1, 8), &t1);
    t1 = multiply(&square_n(&t2, 16), &t2);
    t2 = multiply(&square_n(&t1, 32), &t1);
    t1 = multiply(&square_n(&t2, 64), &t2);
    t1 = square_n(&t1, 62);
    t2.zeroize();
    t1
}

// BC's `Reduce`: 2^192 = 2^64 + 1, by sums of the high words, then one masked subtraction
// where BC branches.
fn reduce(xx: &[u32; 12]) -> [u32; 6] {
    let w = |i: usize| u64::from(xx[i]);
    let (xx06, xx07, xx08, xx09, xx10, xx11) = (w(6), w(7), w(8), w(9), w(10), w(11));
    let mut z = [0; 6];

    let mut t0 = xx06 + xx10;
    let mut t1 = xx07 + xx11;
    let mut cc = w(0) + t0;
    let z0 = cc as u32;
    cc >>= 32;
    cc += w(1) + t1;
    z[1] = cc as u32;
    cc >>= 32;

    t0 += xx08;
    t1 += xx09;
    cc += w(2) + t0;
    let mut z2 = u64::from(cc as u32);
    cc >>= 32;
    cc += w(3) + t1;
    z[3] = cc as u32;
    cc >>= 32;

    t0 -= xx06;
    t1 -= xx07;
    cc += w(4) + t0;
    z[4] = cc as u32;
    cc >>= 32;
    cc += w(5) + t1;
    z[5] = cc as u32;
    cc >>= 32;

    z2 += cc;
    cc += u64::from(z0);
    z[0] = cc as u32;
    cc >>= 32;
    // BC skips this when cc is 0, which leaves z as it is.
    cc += u64::from(z[1]);
    z[1] = cc as u32;
    z2 += cc >> 32;
    z[2] = z2 as u32;

    // BC's `IncAt(6, z, 3)` for the carry out of z2.
    let mut c = z2 >> 32;
    debug_assert!(c == 0 || c == 1);
    for limb in &mut z[3..] {
        c += u64::from(*limb);
        *limb = c as u32;
        c >>= 32;
    }
    nat::reduce_once(&z, c as u32, &P)
}
