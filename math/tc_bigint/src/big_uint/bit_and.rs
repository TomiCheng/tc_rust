//! Bitwise AND operations for [`BigUint`].

use core::ops::{BitAnd, BitAndAssign};

use crate::{BigUint, Limb};

impl BitAnd<&BigUint> for &BigUint {
    type Output = BigUint;

    fn bitand(self, rhs: &BigUint) -> Self::Output {
        BigUint::from_limbs(
            self.limbs
                .iter()
                .zip(&rhs.limbs)
                .map(|(left, right)| Limb::new(left.to_word() & right.to_word()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitand_supports_all_ownership_forms() {
        let left = BigUint::from(0b1100_u8);
        let right = BigUint::from(0b1010_u8);
        let expected = BigUint::from(0b1000_u8);
        assert_eq!(&left & &right, expected);
        assert_eq!(&left & right.clone(), expected);
        assert_eq!(left.clone() & &right, expected);
        assert_eq!(left.clone() & right.clone(), expected);
    }
}
