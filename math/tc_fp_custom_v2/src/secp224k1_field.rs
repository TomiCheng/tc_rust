// BC's `SecP224K1Field`: p = 2^224 - 2^32 - 6803 on seven limbs.

use crate::{mod_inverse, nat};
use tc_zeroize::Zeroize;

pub(crate) const P: [u32; 7] = [
    0xFFFF_E56D,
    0xFFFF_FFFE,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
];

// BC's `PInv33`: 2^224 mod p = 2^32 + 6803.
const P_INV_33: u64 = 0x1A93;

// BC's `PRECOMP_POW2`: a square root of -1, 2^((p - 1) / 4).
const PRECOMP_POW2: [u32; 7] = [
    0x33BF_D202,
    0xDCFA_D133,
    0x2287_624A,
    0xC381_1BA8,
    0xA855_58FC,
    0x1EAE_F5D7,
    0x8EDF_154C,
];

pub(crate) fn multiply(x: &[u32; 7], y: &[u32; 7]) -> [u32; 7] {
    let mut tt = nat::mul::<7, 14>(x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u32; 7]) -> [u32; 7] {
    let mut tt = nat::square::<7, 14>(x);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

// BC's `SquareN`: x^(2^n), for n of at least one.
pub(crate) fn square_n(x: &[u32; 7], n: usize) -> [u32; 7] {
    debug_assert!(n > 0);
    let mut tt = nat::square::<7, 14>(x);
    let mut z = reduce(&tt);
    for _ in 1..n {
        tt = nat::square::<7, 14>(&z);
        z = reduce(&tt);
    }
    tt.zeroize();
    z
}

// BC's `Inv`, through `Mod.ModOddInverse`; zero for zero.
pub(crate) fn invert(x: &[u32; 7]) -> [u32; 7] {
    mod_inverse::mod_odd_inverse::<7, 8>(&P, x).0
}

// BC's `SecP224K1FieldElement.Sqrt`: as p = 5 mod 8, Pocklington's method. x^((p + 3) / 8)
// by its addition chain is one candidate, and that times a square root of -1 the other; BC
// tries them in turn, here the right one is selected by a mask.
pub(crate) fn sqrt(x1: &[u32; 7]) -> [u32; 7] {
    let mut x2 = multiply(&square(x1), x1);
    let mut x3 = multiply(&square(&x2), x1);
    let mut x4 = multiply(&square(&x3), x1);
    let mut x8 = multiply(&square_n(&x4, 4), &x4);
    let mut x11 = multiply(&square_n(&x8, 3), &x3);
    let mut x19 = multiply(&square_n(&x11, 8), &x8);
    let mut x23 = multiply(&square_n(&x19, 4), &x4);
    let mut x42 = multiply(&square_n(&x23, 19), &x19);
    let mut x84 = multiply(&square_n(&x42, 42), &x42);
    let mut x107 = multiply(&square_n(&x84, 23), &x23);
    let mut x191 = multiply(&square_n(&x107, 84), &x84);
    let mut t1 = multiply(&square_n(&x191, 20), &x19);
    t1 = multiply(&square_n(&t1, 3), x1);
    t1 = multiply(&square_n(&t1, 2), x1);
    t1 = multiply(&square_n(&t1, 4), &x3);
    t1 = square(&t1);
    for t in [
        &mut x2, &mut x3, &mut x4, &mut x8, &mut x11, &mut x19, &mut x23, &mut x42, &mut x84,
        &mut x107, &mut x191,
    ] {
        t.zeroize();
    }
    let other = multiply(&t1, &PRECOMP_POW2);
    let first = nat::is_zero(&nat::sub(&square(&t1), x1).0);
    let root = nat::select(nat::mask(first ^ 1), &t1, &other);
    t1.zeroize();
    root
}

// BC's `Reduce`, by `Mul33Add` and `Mul33DWordAdd`.
fn reduce(xx: &[u32; 14]) -> [u32; 7] {
    nat::reduce33(xx, P_INV_33, &P)
}
