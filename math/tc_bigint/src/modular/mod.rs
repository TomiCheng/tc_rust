//! Reusable modular arithmetic over little-endian integers.

mod form;
mod inverse;
mod monty;
mod mul;
mod ops;
#[cfg(feature = "alloc")]
mod padded_form;
#[cfg(feature = "alloc")]
mod padded_inverse;
#[cfg(feature = "alloc")]
mod padded_mul;
#[cfg(feature = "alloc")]
mod padded_params;
#[cfg(feature = "alloc")]
mod padded_pow;
#[cfg(all(test, feature = "alloc"))]
mod padded_tests;
mod params;
mod pow;
mod traits;

pub use form::FixedMontyForm;
#[cfg(feature = "alloc")]
pub use form::MontyForm;
#[cfg(feature = "alloc")]
pub use inverse::{
    ModOddInverseError, checked_mod_odd_inverse, checked_mod_odd_inverse_var, mod_odd_inverse,
    mod_odd_inverse_var, mod_odd_is_coprime, mod_odd_is_coprime_var,
};
#[cfg(feature = "alloc")]
pub use padded_form::PaddedMontyForm;
#[cfg(feature = "alloc")]
pub use padded_params::PaddedMontyParams;
pub use params::FixedMontyParams;
#[cfg(feature = "alloc")]
pub use params::MontyParams;
pub use traits::{Monty, MontyInteger, Retrieve};

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
    use crate::limb::slice::tests::{fixed_is_one, fixed_is_zero};

    type Words = [Limb; 2];

    #[test]
    fn fixed_modular_helpers_cover_reduction_and_non_invertible_values() {
        let three: Words = [Limb::new(3), Limb::new(0)];
        let four: Words = [Limb::new(4), Limb::new(0)];
        let seven: Words = [Limb::new(7), Limb::new(0)];

        assert_eq!(
            fixed_mod_inverse(&three, &seven),
            Some([Limb::new(5), Limb::new(0)])
        );
        assert_eq!(
            fixed_mod_inverse(&four, &[Limb::new(6), Limb::new(0)]),
            None
        );
        assert_eq!(
            fixed_mod_pow(&three, &four, &seven),
            [Limb::new(4), Limb::new(0)]
        );
        assert_eq!(
            fixed_mul_mod(&three, &four, &seven),
            [Limb::new(5), Limb::new(0)]
        );
        assert_eq!(
            fixed_add_mod(&three, &four, &seven),
            [Limb::new(0), Limb::new(0)]
        );
        assert_eq!(
            fixed_add_mod(&[Limb::new(1), Limb::new(0)], &three, &seven),
            four
        );
        assert_eq!(
            fixed_sub_mod(&four, &three, &seven),
            [Limb::new(1), Limb::new(0)]
        );
        assert_eq!(
            fixed_sub_mod(&three, &four, &seven),
            [Limb::new(6), Limb::new(0)]
        );
        assert_eq!(fixed_one_mod(&seven), [Limb::new(1), Limb::new(0)]);
        assert_eq!(
            fixed_one_mod(&[Limb::new(1), Limb::new(0)]),
            [Limb::new(0), Limb::new(0)]
        );
        assert!(fixed_is_zero(&[Limb::new(0), Limb::new(0)]));
        assert!(fixed_is_one(&[Limb::new(1), Limb::new(0)]));
        assert!(!fixed_is_one(&[Limb::new(1), Limb::new(1)]));
    }
}
