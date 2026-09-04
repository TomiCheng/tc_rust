//! Bit inspection and mutation for [`FixedBigInt`].

use crate::traits::{AndNot, BitOps};
use crate::{FixedBigInt, Limb, Word};

impl<const N: usize> FixedBigInt<N> {
    /// Returns the significant bit length excluding sign extension.
    pub fn bit_length(&self) -> usize {
        self.limbs
            .iter()
            .rposition(|word| {
                if self.is_negative() {
                    word.0 != Word::MAX
                } else {
                    word.0 != 0
                }
            })
            .map_or(0, |index| {
                let word = if self.is_negative() {
                    !self.limbs[index].0
                } else {
                    self.limbs[index].0
                };
                index * Word::BITS as usize + (Word::BITS - word.leading_zeros()) as usize
            })
    }

    /// Counts bits which differ from sign extension.
    pub fn bit_count(&self) -> usize {
        if self.is_negative() {
            self.limbs
                .iter()
                .map(|word| (!word.0).count_ones() as usize)
                .sum()
        } else {
            self.limbs
                .iter()
                .map(|word| word.0.count_ones() as usize)
                .sum()
        }
    }

    /// Counts zero bits from the most-significant end of the representation.
    pub fn leading_zeros(&self) -> usize {
        self.limbs
            .iter()
            .rev()
            .try_fold(0_usize, |count, limb| {
                if limb.0 == 0 {
                    Ok(count + Word::BITS as usize)
                } else {
                    Err(count + limb.0.leading_zeros() as usize)
                }
            })
            .unwrap_or_else(|count| count)
    }

    /// Tests bit `index`, including mathematical sign extension above the width.
    pub fn test_bit(&self, index: usize) -> bool {
        self.limbs
            .get(index / Word::BITS as usize)
            .map_or(self.is_negative(), |word| {
                word.0 >> (index % Word::BITS as usize) & 1 != 0
            })
    }

    /// Returns a value with bit `index` set.
    pub fn set_bit(&self, index: usize) -> Self {
        assert!(
            index < N * Word::BITS as usize,
            "bit index is outside fixed width"
        );
        let mut result = *self;
        result.limbs[index / Word::BITS as usize].0 |= (1 as Word) << (index % Word::BITS as usize);
        result
    }

    /// Returns a value with bit `index` cleared.
    pub fn clear_bit(&self, index: usize) -> Self {
        assert!(
            index < N * Word::BITS as usize,
            "bit index is outside fixed width"
        );
        let mut result = *self;
        result.limbs[index / Word::BITS as usize].0 &=
            !((1 as Word) << (index % Word::BITS as usize));
        result
    }

    /// Returns a value with bit `index` flipped.
    pub fn flip_bit(&self, index: usize) -> Self {
        assert!(
            index < N * Word::BITS as usize,
            "bit index is outside fixed width"
        );
        let mut result = *self;
        result.limbs[index / Word::BITS as usize].0 ^= (1 as Word) << (index % Word::BITS as usize);
        result
    }

    /// Returns the index of the least-significant set bit.
    pub fn lowest_set_bit(&self) -> Option<usize> {
        self.limbs
            .iter()
            .enumerate()
            .find(|(_, word)| word.0 != 0)
            .map(|(index, word)| index * Word::BITS as usize + word.0.trailing_zeros() as usize)
    }

    /// Returns `self & !other`.
    pub fn and_not(&self, other: &Self) -> Self {
        Self {
            limbs: core::array::from_fn(|index| Limb(self.limbs[index].0 & !other.limbs[index].0)),
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
