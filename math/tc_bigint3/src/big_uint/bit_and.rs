//! Bitwise AND operations for [`BigUint`].

use core::ops::{BitAnd, BitAndAssign};

use crate::traits::AndNot;
use crate::{BigUint, Limb};

impl BigUint {
    /// Returns `self & !other` within this value's finite magnitude.
    pub fn and_not(&self, other: &Self) -> Self {
        Self::from_limbs(
            self.limbs
                .iter()
                .enumerate()
                .map(|(index, word)| {
                    Limb(word.0 & !other.limbs.get(index).map_or(0, |other| other.0))
                })
                .collect(),
        )
    }
}

impl BitAnd<&BigUint> for &BigUint {
    type Output = BigUint;

    fn bitand(self, rhs: &BigUint) -> Self::Output {
        BigUint::from_limbs(
            self.limbs
                .iter()
                .zip(&rhs.limbs)
                .map(|(left, right)| Limb(left.0 & right.0))
                .collect(),
        )
    }
}

impl BitAnd<BigUint> for &BigUint {
    type Output = BigUint;

    fn bitand(self, rhs: BigUint) -> Self::Output {
        self & &rhs
    }
}

impl BitAnd<&BigUint> for BigUint {
    type Output = BigUint;

    fn bitand(self, rhs: &BigUint) -> Self::Output {
        &self & rhs
    }
}

impl BitAnd<BigUint> for BigUint {
    type Output = BigUint;

    fn bitand(self, rhs: BigUint) -> Self::Output {
        &self & &rhs
    }
}

impl BitAndAssign<&BigUint> for BigUint {
    fn bitand_assign(&mut self, rhs: &BigUint) {
        *self = &*self & rhs;
    }
}

impl BitAndAssign for BigUint {
    fn bitand_assign(&mut self, rhs: Self) {
        *self &= &rhs;
    }
}

impl AndNot for BigUint {
    type Output = Self;

    fn and_not(&self, rhs: &Self) -> Self::Output {
        BigUint::and_not(self, rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitand_supports_all_ownership_forms_and_and_not() {
        let left = BigUint::from(0b1100_u8);
        let right = BigUint::from(0b1010_u8);
        let expected = BigUint::from(0b1000_u8);
        assert_eq!(&left & &right, expected);
        assert_eq!(&left & right.clone(), expected);
        assert_eq!(left.clone() & &right, expected);
        assert_eq!(left.clone() & right.clone(), expected);
        assert_eq!(left.and_not(&right), BigUint::from(0b0100_u8));
        assert_eq!(AndNot::and_not(&left, &right), BigUint::from(0b0100_u8));
    }
}
