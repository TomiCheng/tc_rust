// BC's `SecP224R1Field`: p = 2^224 - 2^96 + 1 on seven limbs.

use crate::{mod_inverse, nat};
use tc_zeroize::Zeroize;

pub(crate) const P: [u32; 7] = [
    0x0000_0001,
    0x0000_0000,
    0x0000_0000,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
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
    let mut z = square(x);
    for _ in 1..n {
        z = square(&z);
    }
    z
}

// BC's `Inv`, through `Mod.ModOddInverse`; zero for zero.
pub(crate) fn invert(x: &[u32; 7]) -> [u32; 7] {
    mod_inverse::mod_odd_inverse::<7, 8>(&P, x).0
}

// BC's `SecP224R1FieldElement.Sqrt`: p - 1 is 2^96 times an odd number, so BC takes the
// Lehmer sequences of its `TrySqrt` from a random r, adding one to r until one gives the root.
// Any r works, so r starts at 1 here, which needs no random source. Zero for a non-square.
// Variable time: only for public values, as when a point is decompressed.
pub(crate) fn sqrt(x: &[u32; 7]) -> [u32; 7] {
    let one = {
        let mut one = [0; 7];
        one[0] = 1;
        one
    };
    if nat::is_zero(x) == 1 || *x == one {
        return *x;
    }
    if !is_square(x) {
        return [0; 7];
    }
    let nc = nat::sub_mod(&[0; 7], x, &P);
    let mut r = one;
    loop {
        if let Some(t) = try_sqrt(&nc, &r) {
            return t;
        }
        r = nat::add_mod(&r, &one, &P);
    }
}

// BC's `IsSquare`: Euler's criterion, x^((p - 1) / 2) = 1.
fn is_square(x: &[u32; 7]) -> bool {
    let mut t1 = *x;
    for i in 0..7 {
        let t2 = t1;
        t1 = multiply(&square_n(&t1, 1 << i), &t2);
    }
    t1 = square_n(&t1, 95);
    let mut one = [0; 7];
    one[0] = 1;
    t1 == one
}

fn twice(x: &[u32; 7]) -> [u32; 7] {
    nat::add_mod(x, x, &P)
}

// BC's `RS`: one doubling step of the sequences.
fn rs(d: &mut [u32; 7], e: &mut [u32; 7], f: &mut [u32; 7]) {
    *e = twice(&multiply(e, d));
    let t = square(d);
    *d = nat::add_mod(f, &t, &P);
    *f = twice(&twice(&multiply(f, &t)));
}

// BC's `RM`: one addition step of the sequences.
fn rm(
    nc: &[u32; 7],
    d0: &[u32; 7],
    e0: &[u32; 7],
    d1: &mut [u32; 7],
    e1: &mut [u32; 7],
    f1: &mut [u32; 7],
) {
    let t = multiply(&multiply(e1, e0), nc);
    let sum = nat::add_mod(&multiply(d1, d0), &t, &P);
    let t = multiply(d1, e0);
    *d1 = sum;
    *e1 = nat::add_mod(&multiply(e1, d0), &t, &P);
    *f1 = multiply(&square(e1), nc);
}

// BC's `RP`: the sequences to the index 2^7 - 1.
fn rp(nc: &[u32; 7], d1: &mut [u32; 7], e1: &mut [u32; 7], f1: &mut [u32; 7]) {
    *f1 = *nc;
    for i in 0..7 {
        let (d0, e0) = (*d1, *e1);
        for _ in 0..1 << i {
            rs(d1, e1, f1);
        }
        rm(nc, &d0, &e0, d1, e1, f1);
    }
}

// BC's `TrySqrt`: the root from the sequences of r, or `None` for this r.
fn try_sqrt(nc: &[u32; 7], r: &[u32; 7]) -> Option<[u32; 7]> {
    let mut d1 = *r;
    let mut e1 = [0; 7];
    e1[0] = 1;
    let mut f1 = [0; 7];
    rp(nc, &mut d1, &mut e1, &mut f1);
    for _ in 1..96 {
        let (d0, e0) = (d1, e1);
        rs(&mut d1, &mut e1, &mut f1);
        if nat::is_zero(&d1) == 1 {
            return Some(multiply(&invert(&e0), &d0));
        }
    }
    None
}

// BC's `Reduce`: 2^224 = 2^96 - 1, by signed sums of the high words, offset by n to keep the
// running carry from going below zero, then one masked subtraction where BC branches.
fn reduce(xx: &[u32; 14]) -> [u32; 7] {
    let w = |i: usize| i64::from(xx[i]);
    const N: i64 = 1;
    let (xx10, xx11, xx12, xx13) = (w(10), w(11), w(12), w(13));
    let mut z = [0; 7];

    let t0 = w(7) + xx11 - N;
    let t1 = w(8) + xx12;
    let t2 = w(9) + xx13;

    let mut cc = w(0) - t0;
    let mut z0 = i64::from(cc as u32);
    cc >>= 32;
    cc += w(1) - t1;
    z[1] = cc as u32;
    cc >>= 32;
    cc += w(2) - t2;
    z[2] = cc as u32;
    cc >>= 32;
    cc += w(3) + t0 - xx10;
    let mut z3 = i64::from(cc as u32);
    cc >>= 32;
    cc += w(4) + t1 - xx11;
    z[4] = cc as u32;
    cc >>= 32;
    cc += w(5) + t2 - xx12;
    z[5] = cc as u32;
    cc >>= 32;
    cc += w(6) + xx10 - xx13;
    z[6] = cc as u32;
    cc >>= 32;
    cc += N;
    debug_assert!(cc >= 0);

    z3 += cc;
    z0 -= cc;
    z[0] = z0 as u32;
    // BC skips this when the borrow out of z0 is 0, which leaves z as it is.
    cc = z0 >> 32;
    cc += i64::from(z[1]);
    z[1] = cc as u32;
    cc >>= 32;
    cc += i64::from(z[2]);
    z[2] = cc as u32;
    z3 += cc >> 32;
    z[3] = z3 as u32;

    // BC's `IncAt(7, z, 4)` for the carry out of z3.
    let mut c = (z3 >> 32) as u64;
    debug_assert!(c == 0 || c == 1);
    for limb in &mut z[4..] {
        c += u64::from(*limb);
        *limb = c as u32;
        c >>= 32;
    }
    nat::reduce_once(&z, c as u32, &P)
}
