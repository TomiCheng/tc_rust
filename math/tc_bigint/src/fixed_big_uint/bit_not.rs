//! Bitwise complement for [`FixedBigUint`].

use core::ops::Not;

use crate::{FixedBigUint, Limb};

impl<const N: usize> Not for FixedBigUint<N> {
    type Output = Self;
    fn not(self) -> Self {
        Self {
            limbs: self.limbs.map(|word| Limb::new(!word.to_word())),
        }
    }
}

impl<const N: usize> Not for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;
    fn not(self) -> Self::Output {
        !*self
    }
}
