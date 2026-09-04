//! Negation for [`FixedBigInt`].

use core::ops::Neg;

use crate::traits::{CheckedNeg, WrappingNeg};
use crate::{FixedBigInt, arithmetic};

impl<const N: usize> Neg for FixedBigInt<N> {
    type Output = Self;
    fn neg(self) -> Self {
        assert!(
            self != Self::min_value(),
            "attempted to negate with overflow"
        );
        Self {
            limbs: arithmetic::fixed_wrapping_neg(&self.limbs),
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
            limbs: arithmetic::fixed_wrapping_neg(&self.limbs),
        })
    }
}

impl<const N: usize> WrappingNeg for FixedBigInt<N> {
    fn wrapping_neg(&self) -> Self {
        Self {
            limbs: arithmetic::fixed_wrapping_neg(&self.limbs),
        }
    }
}
