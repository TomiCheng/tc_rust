//! Bitwise XOR operations for [`FixedBigUint`].

use core::ops::{BitXor, BitXorAssign};

use crate::{FixedBigUint, Limb};

impl<const N: usize> BitXor for FixedBigUint<N> {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self {
            limbs: crate::LimbArray::new(core::array::from_fn(|index| {
                Limb::new(
                    self.limbs.as_limbs()[index].to_word() ^ rhs.limbs.as_limbs()[index].to_word(),
                )
            })),
        }
    }
}

impl<const N: usize> BitXor<&Self> for FixedBigUint<N> {
    type Output = Self;
    fn bitxor(self, rhs: &Self) -> Self {
        self ^ *rhs
    }
}

impl<const N: usize> BitXor<FixedBigUint<N>> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;
    fn bitxor(self, rhs: FixedBigUint<N>) -> Self::Output {
        *self ^ rhs
    }
}

impl<const N: usize> BitXor for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;
    fn bitxor(self, rhs: Self) -> Self::Output {
        *self ^ *rhs
    }
}

impl<const N: usize> BitXorAssign<&Self> for FixedBigUint<N> {
    fn bitxor_assign(&mut self, rhs: &Self) {
        *self = *self ^ *rhs;
    }
}

impl<const N: usize> BitXorAssign for FixedBigUint<N> {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self ^= &rhs;
    }
}
