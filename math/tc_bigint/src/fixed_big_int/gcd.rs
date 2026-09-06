//! Greatest common divisor support for [`FixedBigInt`].

use crate::traits::Gcd;
use crate::{FixedBigInt, FixedBigUint};

impl<const N: usize> FixedBigInt<N> {
    /// Returns the non-negative greatest common divisor as an unsigned value.
    pub fn gcd(&self, other: &Self) -> FixedBigUint<N> {
        FixedBigUint::from_limbs(
            crate::LimbArray::new(self.magnitude())
                .gcd(&crate::LimbArray::new(other.magnitude()))
                .into_limbs(),
        )
    }
}

impl<const N: usize> Gcd for FixedBigInt<N> {
    type Output = FixedBigUint<N>;

    fn gcd(&self, rhs: &Self) -> Self::Output {
        FixedBigInt::gcd(self, rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Word;

    type I128 = FixedBigInt<{ 128 / Word::BITS as usize }>;

    #[test]
    fn gcd_is_unsigned() {
        assert_eq!(
            I128::from(-12_i8).gcd(&I128::from(18_i8)),
            FixedBigUint::from(6_u8)
        );
    }
}
