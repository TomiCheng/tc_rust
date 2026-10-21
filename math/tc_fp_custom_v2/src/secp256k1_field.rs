// BC's `SecP256K1Field`: p = 2^256 - 2^32 - 977 on eight limbs.

use crate::nat;
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

const P_MINUS_2: [u32; 8] = [
    0xFFFF_FC2D,
    0xFFFF_FFFE,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
];

// (p + 1) / 4, as p = 3 mod 4.
const SQRT_EXPONENT: [u32; 8] = [
    0xBFFF_FF0C,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0x3FFF_FFFF,
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
    multiply(x, x)
}

// x^(p - 2), zero for zero.
pub(crate) fn invert(x: &[u32; 8]) -> [u32; 8] {
    nat::pow(x, &P_MINUS_2, multiply)
}

// x^((p + 1) / 4), the square root when there is one.
pub(crate) fn sqrt_candidate(x: &[u32; 8]) -> [u32; 8] {
    nat::pow(x, &SQRT_EXPONENT, multiply)
}

// BC's `Reduce`: H·2^256 + L = L + H·(2^32 + 977), twice, the second time for the few bits
// the first leaves above 2^256.
fn reduce(xx: &[u32; 16]) -> [u32; 8] {
    let mut z = [0; 8];
    let mut c = 0u64;
    for i in 0..8 {
        let shifted = if i == 0 { 0 } else { u64::from(xx[7 + i]) };
        c += u64::from(xx[i]) + u64::from(xx[8 + i]) * P_INV_33 + shifted;
        z[i] = c as u32;
        c >>= 32;
    }
    let t = c + u64::from(xx[15]);

    let low = t * P_INV_33;
    let mut cc = u64::from(z[0]) + (low & 0xFFFF_FFFF);
    z[0] = cc as u32;
    cc >>= 32;
    cc += u64::from(z[1]) + (low >> 32) + (t & 0xFFFF_FFFF);
    z[1] = cc as u32;
    cc >>= 32;
    cc += u64::from(z[2]) + (t >> 32);
    z[2] = cc as u32;
    cc >>= 32;
    for limb in &mut z[3..] {
        cc += u64::from(*limb);
        *limb = cc as u32;
        cc >>= 32;
    }
    debug_assert!(cc == 0 || cc == 1);
    nat::reduce_once(&z, cc as u32, &P)
}
