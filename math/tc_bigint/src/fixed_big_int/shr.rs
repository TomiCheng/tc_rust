//! Right shifts for [`FixedBigInt`].

use core::ops::{Shr, ShrAssign};

use crate::traits::CheckedShr;
use crate::{FixedBigInt, Limb, Word};

impl<const N: usize> Shr<usize> for FixedBigInt<N> {
    type Output = Self;
    fn shr(self, shift: usize) -> Self {
        assert!(
            shift < N * Word::BITS as usize,
            "attempted to shift right with overflow"
        );
        let word_shift = shift / Word::BITS as usize;
        let bit_shift = shift % Word::BITS as usize;
        let extension = if self.is_negative() { Word::MAX } else { 0 };
        let limbs = core::array::from_fn(|index| {
            let source = index + word_shift;
            let low = self.limbs.get(source).map_or(extension, |word| word.to_word());
            let mut value = low >> bit_shift;
            if bit_shift != 0 {
                let high = self.limbs.get(source + 1).map_or(extension, |word| word.to_word());
                value |= high << (Word::BITS as usize - bit_shift);
            }
            Limb::new(value)
        });
        Self { limbs }
    }
}

impl<const N: usize> Shr<usize> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;
    fn shr(self, shift: usize) -> Self::Output {
        *self >> shift
    }
}

impl<const N: usize> CheckedShr for FixedBigInt<N> {
    fn checked_shr(&self, rhs: u32) -> Option<Self> {
        let shift = rhs as usize;
        (shift < N * Word::BITS as usize).then(|| *self >> shift)
    }
}

impl<const N: usize> ShrAssign<usize> for FixedBigInt<N> {
    fn shr_assign(&mut self, rhs: usize) {
        *self = *self >> rhs;
    }
}
