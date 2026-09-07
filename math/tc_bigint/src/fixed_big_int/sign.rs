//! Signed-value operations for [`FixedBigInt`].

use crate::FixedBigInt;
use crate::traits::Signed;

impl<const N: usize> FixedBigInt<N> {
    /// Returns `-1`, `0`, or `1` according to the value's sign.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::I128;
    ///
    /// assert_eq!(I128::from(-7_i8).sign(), -1);
    /// assert_eq!(I128::zero().sign(), 0);
    /// assert_eq!(I128::from(7_i8).sign(), 1);
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

    /// Returns whether the sign bit is set.
    pub fn is_negative(&self) -> bool {
        FixedBigInt::is_negative_limbs(self.limbs.as_limbs())
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

#[cfg(test)]
mod tests {
    use super::*;

    type I = FixedBigInt<2>;

    #[test]
    fn sign_reports_negative_zero_and_positive_values() {
        assert_eq!(I::from(-1_i8).sign(), -1);
        assert_eq!(I::zero().sign(), 0);
        assert_eq!(I::from(1_i8).sign(), 1);
    }
}
