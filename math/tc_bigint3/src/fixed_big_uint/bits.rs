//! Bit inspection and mutation for [`FixedBigUint`].

use crate::traits::{AndNot, BitOps};
use crate::{FixedBigUint, Limb, Word};

impl<const N: usize> FixedBigUint<N> {
    /// Returns the number of significant bits.
    pub fn bit_length(&self) -> usize {
        self.limbs
            .iter()
            .rposition(|word| word.0 != 0)
            .map_or(0, |index| {
                index * Word::BITS as usize
                    + (Word::BITS - self.limbs[index].0.leading_zeros()) as usize
            })
    }

    /// Counts all set bits.
    pub fn bit_count(&self) -> usize {
        self.limbs
            .iter()
            .map(|word| word.0.count_ones() as usize)
            .sum()
    }

    /// Counts zero bits from the most-significant end of the fixed width.
    pub fn leading_zeros(&self) -> usize {
        N * Word::BITS as usize - self.bit_length()
    }

    /// Tests bit `index`.
    pub fn test_bit(&self, index: usize) -> bool {
        self.limbs
            .get(index / Word::BITS as usize)
            .is_some_and(|word| word.0 >> (index % Word::BITS as usize) & 1 != 0)
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
