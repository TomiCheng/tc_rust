//! Left shifts for [`FixedBigInt`].

use core::ops::{Shl, ShlAssign};

use crate::traits::CheckedShl;
use crate::{FixedBigInt, FixedBigUint, Word};

impl<const N: usize> Shl<usize> for FixedBigInt<N> {
    type Output = Self;
    fn shl(self, shift: usize) -> Self {
        assert!(
            shift < N * Word::BITS as usize,
            "attempted to shift left with overflow"
        );
        let unsigned = FixedBigUint::from_limbs(self.limbs.into_limbs()) << shift;
        Self {
            limbs: crate::LimbArray::new(unsigned.into_limbs()),
        }
    }
}

impl<const N: usize> Shl<usize> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;
    fn shl(self, shift: usize) -> Self::Output {
        *self << shift
    }
}

impl<const N: usize> CheckedShl for FixedBigInt<N> {
    fn checked_shl(&self, rhs: u32) -> Option<Self> {
        let shift = rhs as usize;
        if shift >= N * Word::BITS as usize {
            return None;
        }
        let shifted = *self << shift;
        ((shifted >> shift) == *self).then_some(shifted)
    }
}

impl<const N: usize> ShlAssign<usize> for FixedBigInt<N> {
    fn shl_assign(&mut self, rhs: usize) {
        *self = *self << rhs;
    }
}
