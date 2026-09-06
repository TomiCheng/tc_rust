//! Right shifts for [`FixedBigUint`].

use core::ops::{Shr, ShrAssign};

use crate::traits::CheckedShr;
use crate::{FixedBigUint, Limb, Word};

impl<const N: usize> Shr<usize> for FixedBigUint<N> {
    type Output = Self;
    fn shr(self, shift: usize) -> Self {
        assert!(
            shift < N * Word::BITS as usize,
            "attempted to shift right with overflow"
        );
        let word_shift = shift / Word::BITS as usize;
        let bit_shift = shift % Word::BITS as usize;
        let limbs = core::array::from_fn(|index| {
            let source = index + word_shift;
            if source >= N {
                return Limb::new(0);
            }
            let mut value = self.limbs.as_limbs()[source].to_word() >> bit_shift;
            if bit_shift != 0 && source + 1 < N {
                value |= self.limbs.as_limbs()[source + 1].to_word()
                    << (Word::BITS as usize - bit_shift);
            }
            Limb::new(value)
        });
        Self {
            limbs: crate::LimbArray::new(limbs),
        }
    }
}

impl<const N: usize> Shr<usize> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;
    fn shr(self, shift: usize) -> Self::Output {
        *self >> shift
    }
}

impl<const N: usize> CheckedShr for FixedBigUint<N> {
    fn checked_shr(&self, rhs: u32) -> Option<Self> {
        let shift = rhs as usize;
        (shift < N * Word::BITS as usize).then(|| *self >> shift)
    }
}

impl<const N: usize> ShrAssign<usize> for FixedBigUint<N> {
    fn shr_assign(&mut self, rhs: usize) {
        *self = *self >> rhs;
    }
}
