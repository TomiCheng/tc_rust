//! Bit inspection and mutation for [`BigInt`].

use crate::traits::{AndNot, BitOps, One};
use crate::{BigInt, Word, arithmetic};

impl BigInt {
    /// Returns the significant bit length excluding sign extension.
    pub fn bit_length(&self) -> usize {
        if self.is_negative() {
            (!self).bit_length()
        } else {
            arithmetic::bit_len(&self.limbs)
        }
    }

    /// Counts bits which differ from the infinite sign extension.
    pub fn bit_count(&self) -> usize {
        if self.is_negative() {
            self.limbs
                .iter()
                .map(|word| (!word.to_word()).count_ones() as usize)
                .sum()
        } else {
            self.limbs
                .iter()
                .map(|word| word.to_word().count_ones() as usize)
                .sum()
        }
    }

    /// Tests a bit using infinite two's-complement sign extension.
    pub fn test_bit(&self, index: usize) -> bool {
        let word = index / Word::BITS as usize;
        let bit = index % Word::BITS as usize;
        self.limbs
            .get(word)
            .map_or(self.is_negative(), |word| word.to_word() >> bit & 1 != 0)
    }

    /// Returns a value with `index` set.
    pub fn set_bit(&self, index: usize) -> Self {
        self | &(Self::one() << index)
    }

    /// Returns a value with `index` cleared.
    pub fn clear_bit(&self, index: usize) -> Self {
        self & &!(Self::one() << index)
    }

    /// Returns a value with `index` flipped.
    pub fn flip_bit(&self, index: usize) -> Self {
        self ^ &(Self::one() << index)
    }

    /// Returns the index of the least-significant set bit.
    pub fn lowest_set_bit(&self) -> Option<usize> {
        self.limbs
            .iter()
            .enumerate()
            .find(|(_, word)| word.to_word() != 0)
            .map(|(index, word)| {
                index * Word::BITS as usize + word.to_word().trailing_zeros() as usize
            })
    }

    /// Returns `self & !other`.
    pub fn and_not(&self, other: &Self) -> Self {
        self & &!other
    }
}

impl BitOps for BigInt {
    type Output = Self;
    fn bit_length(&self) -> usize {
        BigInt::bit_length(self)
    }
    fn bit_count(&self) -> usize {
        BigInt::bit_count(self)
    }
    fn test_bit(&self, index: usize) -> bool {
        BigInt::test_bit(self, index)
    }
    fn set_bit(&self, index: usize) -> Self {
        BigInt::set_bit(self, index)
    }
    fn clear_bit(&self, index: usize) -> Self {
        BigInt::clear_bit(self, index)
    }
    fn flip_bit(&self, index: usize) -> Self {
        BigInt::flip_bit(self, index)
    }
    fn lowest_set_bit(&self) -> Option<usize> {
        BigInt::lowest_set_bit(self)
    }
}

impl AndNot for BigInt {
    type Output = Self;
    fn and_not(&self, rhs: &Self) -> Self {
        BigInt::and_not(self, rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn and_not_uses_infinite_sign_extension() {
        let value = BigInt::from(0x1234_u16);
        let mask = BigInt::from(0x34_u8);
        assert_eq!(value.and_not(&mask), BigInt::from(0x1200_u16));
        assert_eq!(AndNot::and_not(&value, &mask), BigInt::from(0x1200_u16));
    }
}
