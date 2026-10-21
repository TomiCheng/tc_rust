// BC's `SecP192K1Field`: p = 2^192 - 2^32 - 4553 on six limbs.

use crate::{mod_inverse, nat};
use tc_zeroize::Zeroize;

pub(crate) const P: [u32; 6] = [
    0xFFFF_EE37,
    0xFFFF_FFFE,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
];

// BC's `PInv33`: 2^192 mod p = 2^32 + 4553.
const P_INV_33: u64 = 0x11C9;

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

// BC's `SecP192K1FieldElement.Sqrt`: x^((p + 1) / 4) by its addition chain, the square root
// when there is one.
pub(crate) fn sqrt(x1: &[u32; 6]) -> [u32; 6] {
    let mut x2 = multiply(&square(x1), x1);
    let mut x3 = multiply(&square(&x2), x1);
    let mut x6 = multiply(&square_n(&x3, 3), &x3);
    let mut x8 = multiply(&square_n(&x6, 2), &x2);
    let mut x16 = multiply(&square_n(&x8, 8), &x8);
    let mut x19 = multiply(&square_n(&x16, 3), &x3);
    let mut x35 = multiply(&square_n(&x19, 16), &x16);
    let mut x70 = multiply(&square_n(&x35, 35), &x35);
    let mut x140 = multiply(&square_n(&x70, 70), &x70);
    let mut x159 = multiply(&square_n(&x140, 19), &x19);
    let mut t1 = multiply(&square_n(&x159, 20), &x19);
    t1 = multiply(&square_n(&t1, 4), &x3);
    t1 = multiply(&square_n(&t1, 6), &x3);
    t1 = square(&t1);
    for t in [
        &mut x2, &mut x3, &mut x6, &mut x8, &mut x16, &mut x19, &mut x35, &mut x70, &mut x140,
        &mut x159,
    ] {
        t.zeroize();
    }
    t1
}

// BC's `Reduce`, by `Mul33Add` and `Mul33DWordAdd`.
fn reduce(xx: &[u32; 12]) -> [u32; 6] {
    nat::reduce33(xx, P_INV_33, &P)
}
