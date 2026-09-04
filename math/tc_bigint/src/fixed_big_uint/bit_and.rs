//! Bitwise AND operations for [`FixedBigUint`].

use core::ops::{BitAnd, BitAndAssign};

use crate::{FixedBigUint, Limb};

impl<const N: usize> BitAnd for FixedBigUint<N> {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self {
            limbs: core::array::from_fn(|index| Limb(self.limbs[index].0 & rhs.limbs[index].0)),
        }
    }
}

impl<const N: usize> BitAnd<&Self> for FixedBigUint<N> {
    type Output = Self;
    fn bitand(self, rhs: &Self) -> Self {
        self & *rhs
    }
}

impl<const N: usize> BitAnd<FixedBigUint<N>> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;
    fn bitand(self, rhs: FixedBigUint<N>) -> Self::Output {
        *self & rhs
    }
}

impl<const N: usize> BitAnd for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;
    fn bitand(self, rhs: Self) -> Self::Output {
        *self & *rhs
    }
}

impl<const N: usize> BitAndAssign<&Self> for FixedBigUint<N> {
    fn bitand_assign(&mut self, rhs: &Self) {
        *self = *self & *rhs;
    }
}

impl<const N: usize> BitAndAssign for FixedBigUint<N> {
    fn bitand_assign(&mut self, rhs: Self) {
        *self &= &rhs;
    }
}
