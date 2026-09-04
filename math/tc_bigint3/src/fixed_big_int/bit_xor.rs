//! Bitwise XOR operations for [`FixedBigInt`].

use crate::{FixedBigInt, Limb};
use core::ops::{BitXor, BitXorAssign};

impl<const N: usize> BitXor for FixedBigInt<N> {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self {
            limbs: core::array::from_fn(|index| Limb(self.limbs[index].0 ^ rhs.limbs[index].0)),
        }
    }
}

impl<const N: usize> BitXor<&Self> for FixedBigInt<N> {
    type Output = Self;
    fn bitxor(self, rhs: &Self) -> Self {
        self ^ *rhs
    }
}

impl<const N: usize> BitXor<FixedBigInt<N>> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;
    fn bitxor(self, rhs: FixedBigInt<N>) -> Self::Output {
        *self ^ rhs
    }
}

impl<const N: usize> BitXor for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;
    fn bitxor(self, rhs: Self) -> Self::Output {
        *self ^ *rhs
    }
}

impl<const N: usize> BitXorAssign<&Self> for FixedBigInt<N> {
    fn bitxor_assign(&mut self, rhs: &Self) {
        *self = *self ^ *rhs;
    }
}

impl<const N: usize> BitXorAssign for FixedBigInt<N> {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self ^= &rhs;
    }
}
