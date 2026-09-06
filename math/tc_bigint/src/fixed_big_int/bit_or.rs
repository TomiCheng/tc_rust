//! Bitwise OR operations for [`FixedBigInt`].

use crate::{FixedBigInt, Limb};
use core::ops::{BitOr, BitOrAssign};

impl<const N: usize> BitOr for FixedBigInt<N> {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self {
            limbs: crate::LimbArray::new(core::array::from_fn(|index| {
                Limb::new(
                    self.limbs.as_limbs()[index].to_word() | rhs.limbs.as_limbs()[index].to_word(),
                )
            })),
        }
    }
}

impl<const N: usize> BitOr<&Self> for FixedBigInt<N> {
    type Output = Self;
    fn bitor(self, rhs: &Self) -> Self {
        self | *rhs
    }
}

impl<const N: usize> BitOr<FixedBigInt<N>> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;
    fn bitor(self, rhs: FixedBigInt<N>) -> Self::Output {
        *self | rhs
    }
}

impl<const N: usize> BitOr for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;
    fn bitor(self, rhs: Self) -> Self::Output {
        *self | *rhs
    }
}

impl<const N: usize> BitOrAssign<&Self> for FixedBigInt<N> {
    fn bitor_assign(&mut self, rhs: &Self) {
        *self = *self | *rhs;
    }
}

impl<const N: usize> BitOrAssign for FixedBigInt<N> {
    fn bitor_assign(&mut self, rhs: Self) {
        *self |= &rhs;
    }
}
