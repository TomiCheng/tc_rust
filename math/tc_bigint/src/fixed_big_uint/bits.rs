//! Bit inspection and mutation for [`FixedBigUint`].

use crate::traits::{AndNot, BitOps};
use crate::{FixedBigUint, Limb, Word};

impl<const N: usize> FixedBigUint<N> {
    /// Returns the number of significant bits.
    pub fn bit_length(&self) -> usize {
        self.limbs
            .into_limbs()
            .iter()
            .rposition(|word| word.to_word() != 0)
            .map_or(0, |index| {
                index * Word::BITS as usize
                    + (Word::BITS - self.limbs.as_limbs()[index].to_word().leading_zeros()) as usize
            })
    }

    /// Counts all set bits.
    pub fn bit_count(&self) -> usize {
        self.limbs
            .into_limbs()
            .iter()
            .map(|word| word.to_word().count_ones() as usize)
            .sum()
    }

    /// Counts zero bits from the most-significant end of the fixed width.
    pub fn leading_zeros(&self) -> usize {
        N * Word::BITS as usize - self.bit_length()
    }

    /// Tests bit `index`.
    pub fn test_bit(&self, index: usize) -> bool {
        self.limbs
            .into_limbs()
            .get(index / Word::BITS as usize)
            .is_some_and(|word| word.to_word() >> (index % Word::BITS as usize) & 1 != 0)
    }

    /// Returns a value with bit `index` set.
    pub fn set_bit(&self, index: usize) -> Self {
        Self {
            limbs: self.limbs.set_bit(index),
        }
    }

    /// Returns a value with bit `index` cleared.
    pub fn clear_bit(&self, index: usize) -> Self {
        Self {
            limbs: self.limbs.clear_bit(index),
        }
    }

    /// Returns a value with bit `index` flipped.
    pub fn flip_bit(&self, index: usize) -> Self {
        Self {
            limbs: self.limbs.flip_bit(index),
        }
    }

    /// Returns the index of the least-significant set bit.
    pub fn lowest_set_bit(&self) -> Option<usize> {
        self.limbs
            .into_limbs()
            .iter()
            .enumerate()
            .find(|(_, word)| word.to_word() != 0)
            .map(|(index, word)| {
                index * Word::BITS as usize + word.to_word().trailing_zeros() as usize
            })
    }

    /// Returns `self & !other`.
    pub fn and_not(&self, other: &Self) -> Self {
        Self {
            limbs: crate::LimbArray::new(core::array::from_fn(|index| {
                Limb::new(
                    self.limbs.as_limbs()[index].to_word()
                        & !other.limbs.as_limbs()[index].to_word(),
                )
            })),
        }
    }
}

impl<const N: usize> BitOps for FixedBigUint<N> {
    type Output = Self;
    fn bit_length(&self) -> usize {
        FixedBigUint::bit_length(self)
    }
    fn bit_count(&self) -> usize {
        FixedBigUint::bit_count(self)
    }
    fn test_bit(&self, index: usize) -> bool {
        FixedBigUint::test_bit(self, index)
    }
    fn set_bit(&self, index: usize) -> Self {
        FixedBigUint::set_bit(self, index)
    }
    fn clear_bit(&self, index: usize) -> Self {
        FixedBigUint::clear_bit(self, index)
    }
    fn flip_bit(&self, index: usize) -> Self {
        FixedBigUint::flip_bit(self, index)
    }
    fn lowest_set_bit(&self) -> Option<usize> {
        FixedBigUint::lowest_set_bit(self)
    }
}

impl<const N: usize> AndNot for FixedBigUint<N> {
    type Output = Self;
    fn and_not(&self, rhs: &Self) -> Self {
        FixedBigUint::and_not(self, rhs)
    }
}
