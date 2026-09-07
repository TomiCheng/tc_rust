//! Bit inspection and mutation for [`FixedBigInt`].

use crate::traits::{AndNot, BitOps};
use crate::{FixedBigInt, Limb, Word};

impl<const N: usize> FixedBigInt<N> {
    /// Returns the significant bit length excluding sign extension.
    pub fn bit_length(&self) -> usize {
        self.limbs
            .into_limbs()
            .iter()
            .rposition(|word| {
                if self.is_negative() {
                    word.to_word() != Word::MAX
                } else {
                    word.to_word() != 0
                }
            })
            .map_or(0, |index| {
                let word = if self.is_negative() {
                    !self.limbs.as_limbs()[index].to_word()
                } else {
                    self.limbs.as_limbs()[index].to_word()
                };
                index * Word::BITS as usize + (Word::BITS - word.leading_zeros()) as usize
            })
    }

    /// Counts bits which differ from sign extension.
    pub fn bit_count(&self) -> usize {
        if self.is_negative() {
            self.limbs
                .into_limbs()
                .iter()
                .map(|word| (!word.to_word()).count_ones() as usize)
                .sum()
        } else {
            self.limbs
                .into_limbs()
                .iter()
                .map(|word| word.to_word().count_ones() as usize)
                .sum()
        }
    }

    /// Counts zero bits from the most-significant end of the representation.
    pub fn leading_zeros(&self) -> usize {
        self.limbs
            .into_limbs()
            .iter()
            .rev()
            .try_fold(0_usize, |count, limb| {
                if limb.to_word() == 0 {
                    Ok(count + Word::BITS as usize)
                } else {
                    Err(count + limb.to_word().leading_zeros() as usize)
                }
            })
            .unwrap_or_else(|count| count)
    }

    /// Tests bit `index`, including mathematical sign extension above the width.
    pub fn test_bit(&self, index: usize) -> bool {
        self.limbs
            .into_limbs()
            .get(index / Word::BITS as usize)
            .map_or(self.is_negative(), |word| {
                word.to_word() >> (index % Word::BITS as usize) & 1 != 0
            })
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

impl<const N: usize> BitOps for FixedBigInt<N> {
    type Output = Self;
    fn bit_length(&self) -> usize {
        FixedBigInt::bit_length(self)
    }
    fn bit_count(&self) -> usize {
        FixedBigInt::bit_count(self)
    }
    fn test_bit(&self, index: usize) -> bool {
        FixedBigInt::test_bit(self, index)
    }
    fn set_bit(&self, index: usize) -> Self {
        FixedBigInt::set_bit(self, index)
    }
    fn clear_bit(&self, index: usize) -> Self {
        FixedBigInt::clear_bit(self, index)
    }
    fn flip_bit(&self, index: usize) -> Self {
        FixedBigInt::flip_bit(self, index)
    }
    fn lowest_set_bit(&self) -> Option<usize> {
        FixedBigInt::lowest_set_bit(self)
    }
}

impl<const N: usize> AndNot for FixedBigInt<N> {
    type Output = Self;
    fn and_not(&self, rhs: &Self) -> Self {
        FixedBigInt::and_not(self, rhs)
    }
}
