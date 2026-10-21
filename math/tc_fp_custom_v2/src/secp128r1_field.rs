// BC's `SecP128R1Field`: p = 2^128 - 2^97 - 1 on four limbs.

use crate::{mod_inverse, nat};
use tc_zeroize::Zeroize;

pub(crate) const P: [u32; 4] = [0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFD];

pub(crate) fn multiply(x: &[u32; 4], y: &[u32; 4]) -> [u32; 4] {
    let mut tt = nat::mul::<4, 8>(x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u32; 4]) -> [u32; 4] {
    let mut tt = nat::square::<4, 8>(x);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

// BC's `SquareN`: x^(2^n), for n of at least one.
pub(crate) fn square_n(x: &[u32; 4], n: usize) -> [u32; 4] {
    debug_assert!(n > 0);
    let mut tt = nat::square::<4, 8>(x);
    let mut z = reduce(&tt);
    for _ in 1..n {
        tt = nat::square::<4, 8>(&z);
        z = reduce(&tt);
    }
    tt.zeroize();
    z
}

// BC's `Inv`, through `Mod.ModOddInverse`; zero for zero.
pub(crate) fn invert(x: &[u32; 4]) -> [u32; 4] {
    mod_inverse::mod_odd_inverse::<4, 5>(&P, x).0
}

// BC's `SecP128R1FieldElement.Sqrt`: x^((p + 1) / 4) = x^(2^126 - 2^95) by its addition
// chain, the square root when there is one.
pub(crate) fn sqrt(x1: &[u32; 4]) -> [u32; 4] {
    let mut x2 = multiply(&square(x1), x1);
    let mut x4 = multiply(&square_n(&x2, 2), &x2);
    let mut x8 = multiply(&square_n(&x4, 4), &x4);
    let mut x10 = multiply(&square_n(&x8, 2), &x2);
    let mut x20 = multiply(&square_n(&x10, 10), &x10);
    let mut x30 = multiply(&square_n(&x20, 10), &x10);
    let mut x31 = multiply(&square(&x30), x1);
    let root = square_n(&x31, 95);
    for t in [
        &mut x2, &mut x4, &mut x8, &mut x10, &mut x20, &mut x30, &mut x31,
    ] {
        t.zeroize();
    }
    root
}

// BC's `Reduce`: 2^128 = 2^97 + 1, folded word by word from the top.
fn reduce(xx: &[u32; 8]) -> [u32; 4] {
    let mut x: [u64; 8] = core::array::from_fn(|i| u64::from(xx[i]));
    x[3] += x[7];
    x[6] += x[7] << 1;
    x[2] += x[6];
    x[5] += x[6] << 1;
    x[1] += x[5];
    x[4] += x[5] << 1;
    x[0] += x[4];
    x[3] += x[4] << 1;

    let mut z = [0; 4];
    z[0] = x[0] as u32;
    x[1] += x[0] >> 32;
    z[1] = x[1] as u32;
    x[2] += x[1] >> 32;
    z[2] = x[2] as u32;
    x[3] += x[2] >> 32;
    z[3] = x[3] as u32;
    reduce32((x[3] >> 32) as u32, z)
}

// BC's `Reduce32`: z + x·(2^97 + 1). BC repeats while a carry is left; from `reduce` the
// carry is gone after two rounds, so both are always taken.
fn reduce32(x: u32, mut z: [u32; 4]) -> [u32; 4] {
    let mut x = x;
    for _ in 0..2 {
        let x4 = u64::from(x);
        let mut c = u64::from(z[0]) + x4;
        z[0] = c as u32;
        c >>= 32;
        c += u64::from(z[1]);
        z[1] = c as u32;
        c >>= 32;
        c += u64::from(z[2]);
        z[2] = c as u32;
        c >>= 32;
        c += u64::from(z[3]) + (x4 << 1);
        z[3] = c as u32;
        x = (c >> 32) as u32;
    }
    debug_assert_eq!(x, 0);
    nat::reduce_once(&z, 0, &P)
}
