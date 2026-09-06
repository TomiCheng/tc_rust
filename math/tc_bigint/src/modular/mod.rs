//! Reusable modular arithmetic over little-endian integers.

mod form;
mod inverse;
mod monty;
mod mul;
mod ops;
mod params;
mod pow;

#[cfg(feature = "alloc")]
pub use form::MontyForm;
pub use form::{FixedMontyForm, Retrieve};
#[cfg(feature = "alloc")]
pub use inverse::{
    ModOddInverseError, checked_mod_odd_inverse, checked_mod_odd_inverse_var, mod_odd_inverse,
    mod_odd_inverse_var, mod_odd_is_coprime, mod_odd_is_coprime_var,
};
pub use monty::{Monty, MontyInteger};
pub use params::FixedMontyParams;
#[cfg(feature = "alloc")]
pub use params::MontyParams;

pub(crate) use inverse::fixed_mod_inverse;
pub(crate) use pow::fixed_mod_pow;
#[cfg(feature = "alloc")]
pub(crate) use pow::mod_pow;

pub(crate) fn exponentiation_window(exponent_bits: usize) -> usize {
    match exponent_bits {
        0..=7 => 1,
        8..=36 => 2,
        37..=140 => 3,
        141..=450 => 4,
        _ => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::mul::{fixed_add_mod, fixed_mul_mod, fixed_one_mod, fixed_sub_mod};
    use super::*;
    use crate::Limb;
    use crate::arithmetic::{fixed_is_one, fixed_is_zero};

    type Words = [Limb; 2];

    #[test]
    fn fixed_modular_helpers_cover_reduction_and_non_invertible_values() {
        let three: Words = [Limb(3), Limb(0)];
        let four: Words = [Limb(4), Limb(0)];
        let seven: Words = [Limb(7), Limb(0)];

        assert_eq!(fixed_mod_inverse(&three, &seven), Some([Limb(5), Limb(0)]));
        assert_eq!(fixed_mod_inverse(&four, &[Limb(6), Limb(0)]), None);
        assert_eq!(fixed_mod_pow(&three, &four, &seven), [Limb(4), Limb(0)]);
        assert_eq!(fixed_mul_mod(&three, &four, &seven), [Limb(5), Limb(0)]);
        assert_eq!(fixed_add_mod(&three, &four, &seven), [Limb(0), Limb(0)]);
        assert_eq!(fixed_add_mod(&[Limb(1), Limb(0)], &three, &seven), four);
        assert_eq!(fixed_sub_mod(&four, &three, &seven), [Limb(1), Limb(0)]);
        assert_eq!(fixed_sub_mod(&three, &four, &seven), [Limb(6), Limb(0)]);
        assert_eq!(fixed_one_mod(&seven), [Limb(1), Limb(0)]);
        assert_eq!(fixed_one_mod(&[Limb(1), Limb(0)]), [Limb(0), Limb(0)]);
        assert!(fixed_is_zero(&[Limb(0), Limb(0)]));
        assert!(fixed_is_one(&[Limb(1), Limb(0)]));
        assert!(!fixed_is_one(&[Limb(1), Limb(1)]));
    }
}
