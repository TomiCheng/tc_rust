//! Bitwise NOT operations for [`BigInt`].

use core::ops::Not;

use crate::{BigInt, Limb, Word};

impl Not for &BigInt {
    type Output = BigInt;

    fn not(self) -> Self::Output {
        let width = self.limbs.len().max(1);
        let extension = if self.is_negative() { Word::MAX } else { 0 };
        BigInt::from_limbs(
            (0..width)
                .map(|index| {
                    Limb::new(
                        !self
                            .limbs
                            .get(index)
                            .map_or(extension, |word| word.to_word()),
                    )
                })
                .collect(),
        )
    }
}

impl Not for BigInt {
    type Output = BigInt;

    fn not(self) -> Self::Output {
        !&self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitnot_supports_owned_and_borrowed_values() {
        let value = BigInt::from(12_i8);
        assert_eq!(!&value, BigInt::from(!12_i8));
        assert_eq!(!value, BigInt::from(!12_i8));
    }
}
