//! Negation for [`FixedBigInt`].

use core::ops::Neg;

use crate::FixedBigInt;
use crate::traits::{CheckedNeg, WrappingNeg};

impl<const N: usize> Neg for FixedBigInt<N> {
    type Output = Self;
    fn neg(self) -> Self {
        assert!(
            self != Self::min_value(),
            "attempted to negate with overflow"
        );
        Self {
            limbs: self.limbs.wrapping_neg(),
        }
    }
}

impl<const N: usize> Neg for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;
    fn neg(self) -> Self::Output {
        -*self
    }
}

impl<const N: usize> CheckedNeg for FixedBigInt<N> {
    fn checked_neg(&self) -> Option<Self> {
        (*self != Self::min_value()).then(|| Self {
            limbs: self.limbs.wrapping_neg(),
        })
    }
}

impl<const N: usize> WrappingNeg for FixedBigInt<N> {
    fn wrapping_neg(&self) -> Self {
        Self {
            limbs: self.limbs.wrapping_neg(),
        }
    }
}
