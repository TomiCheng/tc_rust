//! Negation for [`BigInt`].

use core::ops::Neg;

use crate::BigInt;
use crate::traits::{CheckedNeg, WrappingNeg};

impl BigInt {
    pub(super) fn neg_ref(value: &Self) -> Self {
        let (negative, magnitude) = value.sign_magnitude();
        Self::from_sign_magnitude(!negative, magnitude)
    }
}

impl Neg for &BigInt {
    type Output = BigInt;
    fn neg(self) -> BigInt {
        BigInt::neg_ref(self)
    }
}

impl Neg for BigInt {
    type Output = BigInt;
    fn neg(self) -> BigInt {
        -&self
    }
}

impl CheckedNeg for BigInt {
    fn checked_neg(&self) -> Option<Self> {
        Some(-self)
    }
}

impl WrappingNeg for BigInt {
    fn wrapping_neg(&self) -> Self {
        -self
    }
}
