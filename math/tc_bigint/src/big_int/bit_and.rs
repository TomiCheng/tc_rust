//! Bitwise AND operations for [`BigInt`].

use core::ops::{BitAnd, BitAndAssign};

use crate::{BigInt, Limb, Word};

impl BigInt {
    pub(super) fn bitwise(lhs: &Self, rhs: &Self, operation: impl Fn(Word, Word) -> Word) -> Self {
        let width = lhs.limbs.len().max(rhs.limbs.len());
        let lhs_extension = if lhs.is_negative() { Word::MAX } else { 0 };
        let rhs_extension = if rhs.is_negative() { Word::MAX } else { 0 };
        Self::from_limbs(
            (0..width)
                .map(|index| {
                    Limb::new(operation(
                        lhs.limbs.get(index).map_or(lhs_extension, |word| word.to_word()),
                        rhs.limbs.get(index).map_or(rhs_extension, |word| word.to_word()),
                    ))
                })
                .collect(),
        )
    }
}

impl BitAnd<&BigInt> for &BigInt {
    type Output = BigInt;

    fn bitand(self, rhs: &BigInt) -> Self::Output {
        BigInt::bitwise(self, rhs, |left, right| left & right)
    }
}

impl BitAnd<BigInt> for &BigInt {
    type Output = BigInt;

    fn bitand(self, rhs: BigInt) -> Self::Output {
        self & &rhs
    }
}

impl BitAnd<&BigInt> for BigInt {
    type Output = BigInt;

    fn bitand(self, rhs: &BigInt) -> Self::Output {
        &self & rhs
    }
}

impl BitAnd<BigInt> for BigInt {
    type Output = BigInt;

    fn bitand(self, rhs: BigInt) -> Self::Output {
        &self & &rhs
    }
}

impl BitAndAssign<&BigInt> for BigInt {
    fn bitand_assign(&mut self, rhs: &BigInt) {
        *self = &*self & rhs;
    }
}

impl BitAndAssign for BigInt {
    fn bitand_assign(&mut self, rhs: Self) {
        *self &= &rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitand_supports_all_ownership_forms_and_infinite_sign_extension() {
        let left = BigInt::from(-1_i8);
        let right = BigInt::from(0x1234_u16);
        assert_eq!(&left & &right, right);
        assert_eq!(&left & right.clone(), right);
        assert_eq!(left.clone() & &right, right);
        assert_eq!(left.clone() & right.clone(), right);
    }
}
