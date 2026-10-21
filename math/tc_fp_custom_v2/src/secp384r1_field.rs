// BC's `SecP384R1Field`: p = 2^384 - 2^128 - 2^96 + 2^32 - 1 on twelve limbs.

use crate::nat;
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

const P_MINUS_2: [u32; 12] = [
    0xFFFF_FFFD,
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

// (p + 1) / 4, as p = 3 mod 4.
const SQRT_EXPONENT: [u32; 12] = [
    0x4000_0000,
    0x0000_0000,
    0xC000_0000,
    0xBFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0x3FFF_FFFF,
];

// 2^384 mod p = 2^128 + 2^96 - 2^32 + 1.
const FOLD: [i64; 12] = [1, -1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0];

pub(crate) fn multiply(x: &[u32; 12], y: &[u32; 12]) -> [u32; 12] {
    let mut tt = nat::mul::<12, 24>(x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u32; 12]) -> [u32; 12] {
    multiply(x, x)
}

// x^(p - 2), zero for zero.
pub(crate) fn invert(x: &[u32; 12]) -> [u32; 12] {
    nat::pow(x, &P_MINUS_2, multiply)
}

// x^((p + 1) / 4), the square root when there is one.
pub(crate) fn sqrt_candidate(x: &[u32; 12]) -> [u32; 12] {
    nat::pow(x, &SQRT_EXPONENT, multiply)
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
