// BC's `SecP521R1Field`: the Mersenne prime p = 2^521 - 1, on nine 64-bit limbs where BC takes
// seventeen of 32 bits; the top limb holds nine bits. The products take u128 words.

use crate::{mod_inverse, nat64};
use tc_zeroize::Zeroize;

pub(crate) const P: [u64; 9] = [
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    0x1FF,
];

const P8: u64 = 0x1FF;

pub(crate) fn add(x: &[u64; 9], y: &[u64; 9]) -> [u64; 9] {
    reduce_once(&add_words(x, y))
}

pub(crate) fn subtract(x: &[u64; 9], y: &[u64; 9]) -> [u64; 9] {
    let (z, borrow) = sub_words(x, y);
    let correction = select(borrow.wrapping_neg(), &[0; 9], &P);
    add_words(&z, &correction)
}

pub(crate) fn multiply(x: &[u64; 9], y: &[u64; 9]) -> [u64; 9] {
    let mut tt = nat64::mul::<9, 18>(x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u64; 9]) -> [u64; 9] {
    let mut tt = nat64::square::<9, 18>(x);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

// BC's `SquareN`: x^(2^n), for n of at least one.
pub(crate) fn square_n(x: &[u64; 9], n: usize) -> [u64; 9] {
    debug_assert!(n > 0);
    let mut tt = nat64::square::<9, 18>(x);
    let mut z = reduce(&tt);
    for _ in 1..n {
        tt = nat64::square::<9, 18>(&z);
        z = reduce(&tt);
    }
    tt.zeroize();
    z
}

// BC's `Inv`, through `Mod.ModOddInverse` on the 32-bit halves of the limbs; zero for zero.
pub(crate) fn invert(x: &[u64; 9]) -> [u64; 9] {
    let mut halves = nat64::to_u32::<9, 17>(x);
    let mut inverse =
        mod_inverse::mod_odd_inverse::<17, 18>(&nat64::to_u32::<9, 17>(&P), &halves).0;
    let z = nat64::from_u32::<17, 9>(&inverse);
    halves.zeroize();
    inverse.zeroize();
    z
}

// BC's `SecP521R1FieldElement.Sqrt`: x^((p + 1) / 4) = x^(2^519), the square root when there
// is one.
pub(crate) fn sqrt(x: &[u64; 9]) -> [u64; 9] {
    square_n(x, 519)
}

// 1 when x is below p, else 0.
pub(crate) fn is_below_p(x: &[u64; 9]) -> u64 {
    sub_words(x, &P).1
}

// The big-endian `bytes`, of at most 72.
pub(crate) fn from_be(bytes: &[u8]) -> [u64; 9] {
    debug_assert!(bytes.len() <= 72);
    let mut z = [0; 9];
    for (i, &byte) in bytes.iter().rev().enumerate() {
        z[i / 8] |= u64::from(byte) << (8 * (i % 8));
    }
    z
}

// Fills `output`, of at most 72 bytes, with the low bytes of x, big-endian.
pub(crate) fn to_be(x: &[u64; 9], output: &mut [u8]) {
    debug_assert!(output.len() <= 72);
    for (i, byte) in output.iter_mut().rev().enumerate() {
        *byte = (x[i / 8] >> (8 * (i % 8))) as u8;
    }
}

// The value of the big-endian `bytes` modulo p, a limb at a time from the top.
pub(crate) fn reduce_be(bytes: &[u8]) -> [u64; 9] {
    let mut shift = [0; 9];
    shift[1] = 1;
    let head = bytes.len() % 8;
    let words = (head != 0)
        .then(|| be_word(&bytes[..head]))
        .into_iter()
        .chain(bytes[head..].chunks(8).map(be_word));
    let mut z = [0; 9];
    for word in words {
        let mut low = [0; 9];
        low[0] = word;
        z = add(&multiply(&z, &shift), &low);
    }
    z
}

fn be_word(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0, |acc, &byte| (acc << 8) | u64::from(byte))
}

// BC's `Reduce`: the product's bits from 521 up added to the bits below, as 2^521 = 1. For
// factors below p the sum stays below 2p.
fn reduce(xx: &[u64; 18]) -> [u64; 9] {
    debug_assert!(xx[17] == 0 && xx[16] >> 18 == 0);
    let mut low: [u64; 9] = core::array::from_fn(|i| xx[i]);
    low[8] &= P8;
    let mut high: [u64; 9] = core::array::from_fn(|i| (xx[8 + i] >> 9) | (xx[9 + i] << 55));
    let z = reduce_once(&add_words(&low, &high));
    low.zeroize();
    high.zeroize();
    z
}

// s mod p for s up to 2p: s + 1 reaches bit 521 exactly when s is p or more, and then, with
// that bit dropped, it is s - p. BC branches on the sum; here a mask selects.
fn reduce_once(s: &[u64; 9]) -> [u64; 9] {
    let mut t = [0; 9];
    let mut carry = 1;
    for (ti, &si) in t.iter_mut().zip(s) {
        let (sum, over) = si.overflowing_add(carry);
        *ti = sum;
        carry = u64::from(over);
    }
    let above = t[8] >> 9;
    t[8] &= P8;
    select(above.wrapping_neg(), s, &t)
}

// x + y, the carry out of the nine limbs dropped.
fn add_words(x: &[u64; 9], y: &[u64; 9]) -> [u64; 9] {
    let mut z = [0; 9];
    let mut c = 0u128;
    for ((zi, &xi), &yi) in z.iter_mut().zip(x).zip(y) {
        c += u128::from(xi) + u128::from(yi);
        *zi = c as u64;
        c >>= 64;
    }
    z
}

// The difference and the borrow, 1 when x < y.
fn sub_words(x: &[u64; 9], y: &[u64; 9]) -> ([u64; 9], u64) {
    let mut z = [0; 9];
    let mut borrow = 0;
    for ((zi, &xi), &yi) in z.iter_mut().zip(x).zip(y) {
        let (d0, b0) = xi.overflowing_sub(yi);
        let (d1, b1) = d0.overflowing_sub(borrow);
        *zi = d1;
        borrow = u64::from(b0 | b1);
    }
    (z, borrow)
}

// `b` where `mask` is all ones, `a` where it is zero.
fn select(mask: u64, a: &[u64; 9], b: &[u64; 9]) -> [u64; 9] {
    core::array::from_fn(|i| a[i] ^ (mask & (a[i] ^ b[i])))
}
