//! Bitwise AND operations for [`FixedBigInt`].

use crate::{FixedBigInt, Limb};
use core::ops::{BitAnd, BitAndAssign};

impl<const N: usize> BitAnd for FixedBigInt<N> {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self {
            limbs: core::array::from_fn(|index| Limb(self.limbs[index].0 & rhs.limbs[index].0)),
        }
    }
}

impl<const N: usize> BitAnd<&Self> for FixedBigInt<N> {
    type Output = Self;
    fn bitand(self, rhs: &Self) -> Self {
        self & *rhs
    }
}

impl<const N: usize> BitAnd<FixedBigInt<N>> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;
    fn bitand(self, rhs: FixedBigInt<N>) -> Self::Output {
        *self & rhs
    }
}

impl<const N: usize> BitAnd for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;
    fn bitand(self, rhs: Self) -> Self::Output {
        *self & *rhs
    }
}

impl<const N: usize> BitAndAssign<&Self> for FixedBigInt<N> {
    fn bitand_assign(&mut self, rhs: &Self) {
        *self = *self & *rhs;
    }
}

impl<const N: usize> BitAndAssign for FixedBigInt<N> {
    fn bitand_assign(&mut self, rhs: Self) {
        *self &= &rhs;
    }
}
