//! Modular inverse support for [`BigInt`].

use crate::BigInt;
use crate::traits::{One, Signed, Zero};

impl BigInt {
    /// Returns the modular multiplicative inverse, when it exists.
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        assert!(modulus.is_positive(), "modulus must be positive");
        let mut old_remainder = modulus.clone();
        let mut remainder = self.rem_euclid(modulus);
        let mut old_coefficient = Self::zero();
        let mut coefficient = Self::one();

        while !remainder.is_zero() {
            let quotient = &old_remainder / &remainder;
            let next_remainder = &old_remainder - &quotient * &remainder;
            let next_coefficient = &old_coefficient - &quotient * &coefficient;
            old_remainder = remainder;
            remainder = next_remainder;
            old_coefficient = coefficient;
            coefficient = next_coefficient;
        }

        (old_remainder == Self::one()).then(|| old_coefficient.rem_euclid(modulus))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_matches_known_values() {
        assert_eq!(
            BigInt::from(3_i8).mod_inverse(&BigInt::from(7_i8)),
            Some(BigInt::from(5_i8))
        );
        assert_eq!(BigInt::from(2_i8).mod_inverse(&BigInt::from(4_i8)), None);
    }

    #[test]
    #[should_panic(expected = "modulus must be positive")]
    fn inverse_rejects_non_positive_modulus() {
        let _ = BigInt::from(1_i8).mod_inverse(&BigInt::zero());
    }
}
