//! Signed-value operations for [`BigInt`].

use core::cmp::Ordering;

use crate::traits::{One, Signed, Zero};
use crate::{BigInt, encoding};

impl BigInt {
    /// Returns whether the value is negative.
    pub fn is_negative(&self) -> bool {
        encoding::is_negative(&self.limbs)
    }

    /// Returns the absolute value.
    pub fn abs(&self) -> Self {
        let (_, magnitude) = self.sign_magnitude();
        Self::from_sign_magnitude(false, magnitude)
    }
}

impl Signed for BigInt {
    fn abs(&self) -> Self {
        self.abs()
    }

    fn abs_sub(&self, other: &Self) -> Self {
        if self <= other {
            Self::zero()
        } else {
            self - other
        }
    }

    fn signum(&self) -> Self {
        match self.cmp(&Self::zero()) {
            Ordering::Less => Self::from(-1_i8),
            Ordering::Equal => Self::zero(),
            Ordering::Greater => Self::one(),
        }
    }

    fn is_positive(&self) -> bool {
        !self.is_zero() && !self.is_negative()
    }
    fn is_negative(&self) -> bool {
        self.is_negative()
    }
}
