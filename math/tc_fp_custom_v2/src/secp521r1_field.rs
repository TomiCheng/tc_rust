// BC's `SecP521R1Field`: the Mersenne prime p = 2^521 - 1 on seventeen limbs, the top one of
// nine bits.

use crate::{mod_inverse, nat};
use tc_zeroize::Zeroize;

pub(crate) const P: [u32; 17] = [
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0x0000_01FF,
];

const P16: u32 = 0x1FF;

pub(crate) fn multiply(x: &[u32; 17], y: &[u32; 17]) -> [u32; 17] {
    let mut tt = impl_multiply(x, y);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

pub(crate) fn square(x: &[u32; 17]) -> [u32; 17] {
    let mut tt = impl_square(x);
    let z = reduce(&tt);
    tt.zeroize();
    z
}

// BC's `SquareN`: x^(2^n), for n of at least one.
pub(crate) fn square_n(x: &[u32; 17], n: usize) -> [u32; 17] {
    debug_assert!(n > 0);
    let mut z = square(x);
    for _ in 1..n {
        z = square(&z);
    }
    z
}

// BC's `Inv`, through `Mod.ModOddInverse`; zero for zero.
pub(crate) fn invert(x: &[u32; 17]) -> [u32; 17] {
    mod_inverse::mod_odd_inverse::<17, 18>(&P, x).0
}

// BC's `SecP521R1FieldElement.Sqrt`: x^((p + 1) / 4) = x^(2^519), the square root when there
// is one.
pub(crate) fn sqrt(x: &[u32; 17]) -> [u32; 17] {
    square_n(x, 519)
}

// BC's `ImplMultiply`: `Nat512.Mul` on the low sixteen limbs, then the top limbs' products by
// `Mul31BothAdd`, into thirty-three limbs.
fn impl_multiply(x: &[u32; 17], y: &[u32; 17]) -> [u32; 33] {
    let mut low_x: [u32; 16] = core::array::from_fn(|i| x[i]);
    let mut low_y: [u32; 16] = core::array::from_fn(|i| y[i]);
    let mut product: [u32; 32] = nat::karatsuba_mul::<8, 16, 32>(&low_x, &low_y);
    let (x16, y16) = (u64::from(x[16]), u64::from(y[16]));
    let mut zz = [0; 33];
    zz[..32].copy_from_slice(&product);
    let mut c = 0u64;
    for i in 0..16 {
        c += x16 * u64::from(y[i]) + y16 * u64::from(x[i]) + u64::from(zz[16 + i]);
        zz[16 + i] = c as u32;
        c >>= 32;
    }
    zz[32] = (c + x16 * y16) as u32;
    low_x.zeroize();
    low_y.zeroize();
    product.zeroize();
    zz
}

// BC's `ImplSquare`: `Nat512.Square` on the low sixteen limbs, then the top limb's products by
// `MulWordAddTo`.
fn impl_square(x: &[u32; 17]) -> [u32; 33] {
    let mut low: [u32; 16] = core::array::from_fn(|i| x[i]);
    let mut product: [u32; 32] = nat::karatsuba_square::<8, 16, 32>(&low);
    let x16 = u64::from(x[16]);
    let mut zz = [0; 33];
    zz[..32].copy_from_slice(&product);
    let mut c = 0u64;
    for i in 0..16 {
        c += (x16 << 1) * u64::from(x[i]) + u64::from(zz[16 + i]);
        zz[16 + i] = c as u32;
        c >>= 32;
    }
    zz[32] = (c + x16 * x16) as u32;
    low.zeroize();
    product.zeroize();
    zz
}

// BC's `Reduce`: the product's bits from 521 up, shifted down by `ShiftDownBits`, added to the
// bits below, as 2^521 = 1; then 2^521 - 1 subtracted, by adding one and dropping bit 521, where
// BC branches on the sum and here a mask selects.
fn reduce(xx: &[u32; 33]) -> [u32; 17] {
    let xx32 = xx[32];
    debug_assert!(xx32 >> 18 == 0);
    let mut z = [0; 17];
    let mut carry = xx32;
    for i in (0..16).rev() {
        let next = xx[16 + i];
        z[i] = (next >> 9) | (carry << 23);
        carry = next;
    }
    let mut c = (carry << 23) >> 23;
    c += xx32 >> 9;

    let mut sum = 0u64;
    for i in 0..16 {
        sum += u64::from(z[i]) + u64::from(xx[i]);
        z[i] = sum as u32;
        sum >>= 32;
    }
    c += sum as u32;

    // c > P16, or c = P16 with the low limbs all ones: the sum is p or more.
    let above = P16.wrapping_sub(c) >> 31;
    let low_ones = nat::is_zero(&core::array::from_fn::<u32, 16, _>(|i| !z[i]));
    let at = nat::is_zero(&[c ^ P16]) & low_ones;
    let subtract = above | at;

    let mut inc = u64::from(subtract);
    let mut bumped = [0; 16];
    for i in 0..16 {
        inc += u64::from(z[i]);
        bumped[i] = inc as u32;
        inc >>= 32;
    }
    let low: [u32; 16] = core::array::from_fn(|i| z[i]);
    let low = nat::select(nat::mask(subtract), &low, &bumped);
    let top = nat::select(nat::mask(subtract), &[c], &[(c + inc as u32) & P16])[0];
    z[..16].copy_from_slice(&low);
    z[16] = top;
    z
}
