//! Bitwise complement for [`FixedBigInt`].

use crate::FixedBigInt;
use core::ops::Not;

impl<const N: usize> Not for FixedBigInt<N> {
    type Output = Self;
    fn not(self) -> Self {
        Self {
            limbs: self.limbs.not(),
        }
    }
}

impl<const N: usize> Not for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;
    fn not(self) -> Self::Output {
        !*self
    }
}
