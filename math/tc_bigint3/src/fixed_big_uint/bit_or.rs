//! Bitwise OR operations for [`FixedBigUint`].

use core::ops::{BitOr, BitOrAssign};

use crate::{FixedBigUint, Limb};

impl<const N: usize> BitOr for FixedBigUint<N> {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self {
            limbs: core::array::from_fn(|index| Limb(self.limbs[index].0 | rhs.limbs[index].0)),
        }
    }
}

impl<const N: usize> BitOr<&Self> for FixedBigUint<N> {
    type Output = Self;
    fn bitor(self, rhs: &Self) -> Self {
        self | *rhs
    }
}

impl<const N: usize> BitOr<FixedBigUint<N>> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;
    fn bitor(self, rhs: FixedBigUint<N>) -> Self::Output {
        *self | rhs
    }
}

impl<const N: usize> BitOr for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;
    fn bitor(self, rhs: Self) -> Self::Output {
        *self | *rhs
    }
}

impl<const N: usize> BitOrAssign<&Self> for FixedBigUint<N> {
    fn bitor_assign(&mut self, rhs: &Self) {
        *self = *self | *rhs;
    }
}

impl<const N: usize> BitOrAssign for FixedBigUint<N> {
    fn bitor_assign(&mut self, rhs: Self) {
        *self |= &rhs;
    }
}
