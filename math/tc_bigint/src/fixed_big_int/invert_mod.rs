//! Modular inverse support for [`FixedBigInt`].

use crate::traits::{ModInverse, Signed};
use crate::{FixedBigInt, modular};

impl<const N: usize> FixedBigInt<N> {
    /// Returns the modular multiplicative inverse, when it exists.
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        assert!(modulus.is_positive(), "modulus must be positive");
        let value = self.rem_euclid(modulus);
        modular::fixed_mod_inverse(value.limbs.as_limbs(), modulus.limbs.as_limbs())
            .and_then(|limbs| Self::from_sign_magnitude(false, limbs))
    }
}

impl<const N: usize> ModInverse for FixedBigInt<N> {
    type Output = Self;

    fn mod_inverse(&self, modulus: &Self) -> Option<Self::Output> {
        FixedBigInt::mod_inverse(self, modulus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Word;

    type I128 = FixedBigInt<{ 128 / Word::BITS as usize }>;

    #[test]
    fn inverse_matches_known_value() {
        assert_eq!(
            I128::from(3_i8).mod_inverse(&I128::from(7_i8)),
            Some(I128::from(5_i8))
        );
    }

    #[test]
    #[should_panic(expected = "modulus must be positive")]
    fn inverse_rejects_non_positive_modulus() {
        let _ = I128::from(1_i8).mod_inverse(&I128::zero());
    }
}
