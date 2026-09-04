//! Modular inverse support for [`FixedBigUint`].

use crate::traits::ModInverse;
use crate::{FixedBigUint, modular};

impl<const N: usize> FixedBigUint<N> {
    /// Returns the modular multiplicative inverse, when it exists.
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        modular::fixed_mod_inverse(&self.limbs, &modulus.limbs).map(|limbs| Self { limbs })
    }
}

impl<const N: usize> ModInverse for FixedBigUint<N> {
    type Output = Self;

    fn mod_inverse(&self, modulus: &Self) -> Option<Self::Output> {
        FixedBigUint::mod_inverse(self, modulus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Word;

    type U128 = FixedBigUint<{ 128 / Word::BITS as usize }>;

    #[test]
    fn inverse_matches_known_values() {
        let three = U128::from(3_u8);
        assert_eq!(three.mod_inverse(&U128::from(7_u8)), Some(U128::from(5_u8)));
        assert_eq!(
            three.mod_inverse(&U128::from(10_u8)),
            Some(U128::from(7_u8))
        );

        let max = U128::max_value();
        assert_eq!(
            U128::from(2_u8).mod_inverse(&max),
            Some(U128::from(1_u8) << 127)
        );
    }

    #[test]
    #[should_panic(expected = "modulus must be non-zero")]
    fn inverse_rejects_zero_modulus() {
        let _ = U128::from(1_u8).mod_inverse(&U128::zero());
    }
}
