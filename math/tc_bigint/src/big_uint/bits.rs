//! Bit inspection and mutation for [`BigUint`].

use crate::traits::{AndNot, BitOps};
use crate::{BigUint, Limb, Word};

impl BigUint {
    /// Returns the number of significant bits.
    pub fn bits(&self) -> usize {
        crate::arithmetic::bit_len(&self.limbs)
    }

    /// Returns whether bit `index` is set.
    pub fn test_bit(&self, index: usize) -> bool {
        self.limbs
            .get(index / Word::BITS as usize)
            .is_some_and(|word| word.0 >> (index % Word::BITS as usize) & 1 != 0)
    }

    /// Counts all set bits.
    pub fn bit_count(&self) -> usize {
        self.limbs
            .iter()
            .map(|word| word.0.count_ones() as usize)
            .sum()
    }

    /// Returns a value with bit `index` set.
    pub fn set_bit(&self, index: usize) -> Self {
        let mut limbs = self.limbs.clone();
        let word_index = index / Word::BITS as usize;
        let needed = word_index + 1;
        if limbs.len() < needed {
            limbs.resize(needed, Limb(0));
        }
        limbs[word_index].0 |= (1 as Word) << (index % Word::BITS as usize);
        Self::from_limbs(limbs)
    }

    /// Returns a value with bit `index` cleared.
    pub fn clear_bit(&self, index: usize) -> Self {
        let mut limbs = self.limbs.clone();
        if let Some(word) = limbs.get_mut(index / Word::BITS as usize) {
            word.0 &= !((1 as Word) << (index % Word::BITS as usize));
        }
        Self::from_limbs(limbs)
    }

    /// Returns a value with bit `index` flipped.
    pub fn flip_bit(&self, index: usize) -> Self {
        let mut limbs = self.limbs.clone();
        let word_index = index / Word::BITS as usize;
        let needed = word_index + 1;
        if limbs.len() < needed {
            limbs.resize(needed, Limb(0));
        }
        limbs[word_index].0 ^= (1 as Word) << (index % Word::BITS as usize);
        Self::from_limbs(limbs)
    }

    /// Returns the index of the least-significant set bit.
    pub fn lowest_set_bit(&self) -> Option<usize> {
        self.limbs
            .iter()
            .enumerate()
            .find(|(_, word)| word.0 != 0)
            .map(|(index, word)| index * Word::BITS as usize + word.0.trailing_zeros() as usize)
    }

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

impl BitOps for BigUint {
    type Output = Self;

    fn bit_length(&self) -> usize {
        self.bits()
    }
    fn bit_count(&self) -> usize {
        BigUint::bit_count(self)
    }
    fn test_bit(&self, index: usize) -> bool {
        BigUint::test_bit(self, index)
    }
    fn set_bit(&self, index: usize) -> Self {
        BigUint::set_bit(self, index)
    }
    fn clear_bit(&self, index: usize) -> Self {
        BigUint::clear_bit(self, index)
    }
    fn flip_bit(&self, index: usize) -> Self {
        BigUint::flip_bit(self, index)
    }
    fn lowest_set_bit(&self) -> Option<usize> {
        BigUint::lowest_set_bit(self)
    }
}

impl AndNot for BigUint {
    type Output = Self;

    fn and_not(&self, rhs: &Self) -> Self {
        BigUint::and_not(self, rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn and_not_and_low_bit_changes_preserve_high_limbs() {
        let high = BigUint::from(1_u8).set_bit(127);
        assert_eq!(high.set_bit(0).bits(), 128);
        assert_eq!(high.flip_bit(0).bits(), 128);
        assert_eq!(
            AndNot::and_not(&BigUint::from(0b1100_u8), &BigUint::from(0b1010_u8)),
            BigUint::from(0b0100_u8)
        );
    }
}
