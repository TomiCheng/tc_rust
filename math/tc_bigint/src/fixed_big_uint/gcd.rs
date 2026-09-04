//! Greatest common divisor support for [`FixedBigUint`].

use crate::traits::Gcd;
use crate::{FixedBigUint, arithmetic};

impl<const N: usize> FixedBigUint<N> {
    /// Returns the greatest common divisor.
    pub fn gcd(&self, other: &Self) -> Self {
        Self {
            limbs: arithmetic::fixed_gcd(&self.limbs, &other.limbs),
        }
    }
}

impl<const N: usize> Gcd for FixedBigUint<N> {
    type Output = Self;

    fn gcd(&self, rhs: &Self) -> Self::Output {
        FixedBigUint::gcd(self, rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Word;

    type U128 = FixedBigUint<{ 128 / Word::BITS as usize }>;

    #[test]
    fn gcd_matches_known_value() {
        assert_eq!(U128::from(48_u8).gcd(&U128::from(18_u8)), U128::from(6_u8));
    }
}
