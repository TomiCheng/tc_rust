//! Signed-value operations for [`FixedBigInt`].

use crate::traits::Signed;
use crate::{FixedBigInt, arithmetic};

impl<const N: usize> FixedBigInt<N> {
    /// Returns whether the sign bit is set.
    pub fn is_negative(&self) -> bool {
        arithmetic::fixed_is_negative(&self.limbs)
    }

    /// Returns the absolute value, panicking when called on `MIN`.
    pub fn abs(&self) -> Self {
        if self.is_negative() { -*self } else { *self }
    }
}

impl<const N: usize> Signed for FixedBigInt<N> {
    fn abs(&self) -> Self {
        self.abs()
    }

    fn abs_sub(&self, other: &Self) -> Self {
        if self <= other {
            Self::zero()
        } else {
            *self - *other
        }
    }

    fn signum(&self) -> Self {
        if self.is_negative() {
            Self::from(-1_i8)
        } else if self.is_zero() {
            Self::zero()
        } else {
            Self::from(1_i8)
        }
    }

    fn is_positive(&self) -> bool {
        !self.is_zero() && !self.is_negative()
    }
    fn is_negative(&self) -> bool {
        self.is_negative()
    }
}
