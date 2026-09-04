//! Modular multiplicative inverse over fixed-width limbs.

use super::mul::{fixed_mul_mod, fixed_one_mod, fixed_sub_mod};
use crate::Limb;
use crate::arithmetic::{fixed_div_rem, fixed_is_one, fixed_is_zero};

pub(crate) fn fixed_mod_inverse<const N: usize>(
    value: &[Limb; N],
    modulus: &[Limb; N],
) -> Option<[Limb; N]> {
    assert!(!fixed_is_zero(modulus), "modulus must be non-zero");
    let mut old_remainder = *modulus;
    let mut remainder = fixed_div_rem(value, modulus).1;
    let mut old_coefficient = [Limb(0); N];
    let mut coefficient = fixed_one_mod(modulus);

    while !fixed_is_zero(&remainder) {
        let (quotient, next_remainder) = fixed_div_rem(&old_remainder, &remainder);
        let product = fixed_mul_mod(&quotient, &coefficient, modulus);
        let next_coefficient = fixed_sub_mod(&old_coefficient, &product, modulus);
        old_remainder = remainder;
        remainder = next_remainder;
        old_coefficient = coefficient;
        coefficient = next_coefficient;
    }

    fixed_is_one(&old_remainder).then_some(old_coefficient)
}
