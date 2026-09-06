//! Left shifts for [`FixedBigUint`].

use core::ops::{Shl, ShlAssign};

use crate::traits::CheckedShl;
use crate::{FixedBigUint, Limb, Word};

impl<const N: usize> Shl<usize> for FixedBigUint<N> {
    type Output = Self;
    fn shl(self, shift: usize) -> Self {
        assert!(
            shift < N * Word::BITS as usize,
            "attempted to shift left with overflow"
        );
        let word_shift = shift / Word::BITS as usize;
        let bit_shift = shift % Word::BITS as usize;
        let limbs = core::array::from_fn(|index| {
            if index < word_shift {
                return Limb::new(0);
            }
            let source = index - word_shift;
            let mut value = self.limbs.as_limbs()[source].to_word() << bit_shift;
            if bit_shift != 0 && source != 0 {
                value |= self.limbs.as_limbs()[source - 1].to_word()
                    >> (Word::BITS as usize - bit_shift);
            }
            Limb::new(value)
        });
        Self {
            limbs: crate::LimbArray::new(limbs),
        }
    }
}

impl<const N: usize> Shl<usize> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;
    fn shl(self, shift: usize) -> Self::Output {
        *self << shift
    }
}

impl<const N: usize> CheckedShl for FixedBigUint<N> {
    fn checked_shl(&self, rhs: u32) -> Option<Self> {
        let shift = rhs as usize;
        let width = N * Word::BITS as usize;
        if shift >= width || self.bit_length().saturating_add(shift) > width {
            return None;
        }
        Some(*self << shift)
    }
}

impl<const N: usize> ShlAssign<usize> for FixedBigUint<N> {
    fn shl_assign(&mut self, rhs: usize) {
        *self = *self << rhs;
    }
}
