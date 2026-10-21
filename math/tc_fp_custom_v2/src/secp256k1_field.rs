// BC's `SecP256K1Field`: p = 2^256 - 2^32 - 977 on eight limbs.

use crate::{mod_inverse, nat};
use tc_zeroize::Zeroize;

pub(crate) const P: [u32; 8] = [
    0xFFFF_FC2F,
    0xFFFF_FFFE,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
];

// BC's `PInv33`: 2^256 mod p = 2^32 + 977.
const P_INV_33: u64 = 0x3D1;

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
    let mut z = square(x);
    for _ in 1..n {
        z = square(&z);
    }
    z
}

// BC's `Inv`, through `Mod.ModOddInverse`; zero for zero.
pub(crate) fn invert(x: &[u32; 8]) -> [u32; 8] {
    mod_inverse::mod_odd_inverse::<8, 9>(&P, x).0
}

// BC's `SecP256K1FieldElement.Sqrt`: x^((p + 1) / 4) = x^(2^254 - 2^30 - 2^7 - 2^6 - 2^5 - 2^4
// - 2^2), whose repunits of 223, 22 and 2 ones come from the chain 1, 2, 3, 6, 9, 11, 22, 44,
// 88, 176, 220, 223; the square root when there is one.
pub(crate) fn sqrt(x1: &[u32; 8]) -> [u32; 8] {
    let mut x2 = multiply(&square(x1), x1);
    let mut x3 = multiply(&square(&x2), x1);
    let mut x6 = multiply(&square_n(&x3, 3), &x3);
    let mut x9 = multiply(&square_n(&x6, 3), &x3);
    let mut x11 = multiply(&square_n(&x9, 2), &x2);
    let mut x22 = multiply(&square_n(&x11, 11), &x11);
    let mut x44 = multiply(&square_n(&x22, 22), &x22);
    let mut x88 = multiply(&square_n(&x44, 44), &x44);
    let mut x176 = multiply(&square_n(&x88, 88), &x88);
    let mut x220 = multiply(&square_n(&x176, 44), &x44);
    let mut x223 = multiply(&square_n(&x220, 3), &x3);
    let mut t1 = multiply(&square_n(&x223, 23), &x22);
    t1 = multiply(&square_n(&t1, 6), &x2);
    t1 = square_n(&t1, 2);
    for t in [
        &mut x2, &mut x3, &mut x6, &mut x9, &mut x11, &mut x22, &mut x44, &mut x88, &mut x176,
        &mut x220, &mut x223,
    ] {
        t.zeroize();
    }
    t1
}

// BC's `Reduce`, by `Mul33Add` and `Mul33DWordAdd`.
fn reduce(xx: &[u32; 16]) -> [u32; 8] {
    nat::reduce33(xx, P_INV_33, &P)
}
