// BC's `SecP160R2Field`: p = 2^160 - 2^32 - 21389 on five limbs.

use crate::{mod_inverse, nat};
use tc_zeroize::Zeroize;

pub(crate) const P: [u32; 5] = [
    0xFFFF_AC73,
    0xFFFF_FFFE,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
];

// BC's `PInv33`: 2^160 mod p = 2^32 + 21389.
const P_INV_33: u64 = 0x538D;

pub(crate) fn multiply(x: &[u32; 5], y: &[u32; 5]) -> [u32; 5] {
    let mut tt = nat::mul::<5, 10>(x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u32; 5]) -> [u32; 5] {
    let mut tt = nat::square::<5, 10>(x);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

// BC's `SquareN`: x^(2^n), for n of at least one.
pub(crate) fn square_n(x: &[u32; 5], n: usize) -> [u32; 5] {
    debug_assert!(n > 0);
    let mut z = square(x);
    for _ in 1..n {
        z = square(&z);
    }
    z
}

// BC's `Inv`, through `Mod.ModOddInverse`; zero for zero.
pub(crate) fn invert(x: &[u32; 5]) -> [u32; 5] {
    mod_inverse::mod_odd_inverse::<5, 6>(&P, x).0
}

// BC's `SecP160R2FieldElement.Sqrt`: x^((p + 1) / 4) by its addition chain, the square root
// when there is one.
pub(crate) fn sqrt(x1: &[u32; 5]) -> [u32; 5] {
    let mut x2 = multiply(&square(x1), x1);
    let mut x3 = multiply(&square(&x2), x1);
    let mut x4 = multiply(&square(&x3), x1);
    let mut x7 = multiply(&square_n(&x4, 3), &x3);
    let mut x14 = multiply(&square_n(&x7, 7), &x7);
    let mut x17 = multiply(&square_n(&x14, 3), &x3);
    let mut x31 = multiply(&square_n(&x17, 14), &x14);
    let mut x62 = multiply(&square_n(&x31, 31), &x31);
    let mut x124 = multiply(&square_n(&x62, 62), &x62);
    let mut x127 = multiply(&square_n(&x124, 3), &x3);
    let mut t1 = multiply(&square_n(&x127, 18), &x17);
    t1 = multiply(&square_n(&t1, 2), x1);
    t1 = multiply(&square_n(&t1, 3), &x2);
    t1 = multiply(&square_n(&t1, 6), &x3);
    t1 = multiply(&square_n(&t1, 2), x1);
    for t in [
        &mut x2, &mut x3, &mut x4, &mut x7, &mut x14, &mut x17, &mut x31, &mut x62, &mut x124,
        &mut x127,
    ] {
        t.zeroize();
    }
    t1
}

// BC's `Reduce`, by `Mul33Add` and `Mul33DWordAdd`.
fn reduce(xx: &[u32; 10]) -> [u32; 5] {
    nat::reduce33(xx, P_INV_33, &P)
}
