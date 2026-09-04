//! Signed-value operations for [`BigInt`].

use core::cmp::Ordering;

use crate::traits::{One, Signed, Zero};
use crate::{BigInt, encoding};

impl BigInt {
    /// Returns `-1`, `0`, or `1` according to the value's sign.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint3::BigInt;
    ///
    /// assert_eq!(BigInt::from(-7_i8).sign(), -1);
    /// assert_eq!(BigInt::default().sign(), 0);
    /// assert_eq!(BigInt::from(7_u8).sign(), 1);
    /// ```
    pub fn sign(&self) -> i32 {
        if self.is_negative() {
            -1
        } else if self.is_zero() {
            0
        } else {
            1
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_reports_negative_zero_and_positive_values() {
        assert_eq!(BigInt::from(-1_i8).sign(), -1);
        assert_eq!(BigInt::zero().sign(), 0);
        assert_eq!(BigInt::from(1_u8).sign(), 1);
    }
}
