// BC's `SecP160R1Field`: p = 2^160 - 2^31 - 1 on five limbs.

use crate::{mod_inverse, nat};
use tc_zeroize::Zeroize;

pub(crate) const P: [u32; 5] = [
    0x7FFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
];

// BC's `PInv`: 2^160 mod p = 2^31 + 1.
const P_INV: u64 = 0x8000_0001;

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
    let mut tt = nat::square::<5, 10>(x);
    let mut z = reduce(&tt);
    for _ in 1..n {
        tt = nat::square::<5, 10>(&z);
        z = reduce(&tt);
    }
    tt.zeroize();
    z
}

// BC's `Inv`, through `Mod.ModOddInverse`; zero for zero.
pub(crate) fn invert(x: &[u32; 5]) -> [u32; 5] {
    mod_inverse::mod_odd_inverse::<5, 6>(&P, x).0
}

// BC's `SecP160R1FieldElement.Sqrt`: x^((p + 1) / 4) = x^(2^158 - 2^29) by its addition
// chain, the square root when there is one.
pub(crate) fn sqrt(x1: &[u32; 5]) -> [u32; 5] {
    let mut x2 = multiply(&square(x1), x1);
    let mut x4 = multiply(&square_n(&x2, 2), &x2);
    let mut x8 = multiply(&square_n(&x4, 4), &x4);
    let mut x16 = multiply(&square_n(&x8, 8), &x8);
    let mut x32 = multiply(&square_n(&x16, 16), &x16);
    let mut x64 = multiply(&square_n(&x32, 32), &x32);
    let mut x128 = multiply(&square_n(&x64, 64), &x64);
    let mut x129 = multiply(&square(&x128), x1);
    let root = square_n(&x129, 29);
    for t in [
        &mut x2, &mut x4, &mut x8, &mut x16, &mut x32, &mut x64, &mut x128, &mut x129,
    ] {
        t.zeroize();
    }
    root
}

// BC's `Reduce`: 2^160 = 2^31 + 1, for the high words at once.
fn reduce(xx: &[u32; 10]) -> [u32; 5] {
    let mut z = [0; 5];
    let mut c = 0u64;
    for i in 0..5 {
        let high = u64::from(xx[5 + i]);
        c += u64::from(xx[i]) + high + (high << 31);
        z[i] = c as u32;
        c >>= 32;
    }
    debug_assert!(c >> 32 == 0);
    reduce32(c as u32, z)
}

// BC's `Reduce32`: z + x·(2^31 + 1), by `MulWordsAdd`, then one masked subtraction.
fn reduce32(x: u32, mut z: [u32; 5]) -> [u32; 5] {
    let product = u64::from(x) * P_INV;
    let mut c = u64::from(z[0]) + (product & 0xFFFF_FFFF);
    z[0] = c as u32;
    c >>= 32;
    c += u64::from(z[1]) + (product >> 32);
    z[1] = c as u32;
    c >>= 32;
    for limb in &mut z[2..] {
        c += u64::from(*limb);
        *limb = c as u32;
        c >>= 32;
    }
    nat::reduce_once(&z, c as u32, &P)
}
