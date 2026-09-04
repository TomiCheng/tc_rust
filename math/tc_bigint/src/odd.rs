//! Wrapper which carries a checked odd-value invariant.

use core::ops::Deref;

use crate::BitOps;

/// An integer value known to be odd.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Odd<T>(T);

impl<T: BitOps> Odd<T> {
    /// Creates a wrapper when `value` is odd.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::{Odd, U128};
    ///
    /// assert!(Odd::new(U128::from(7_u8)).is_some());
    /// assert!(Odd::new(U128::from(8_u8)).is_none());
    /// ```
    pub fn new(value: T) -> Option<Self> {
        (value.bit_length() != 0 && value.test_bit(0)).then_some(Self(value))
    }

    /// Extracts the wrapped value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::{Odd, U128};
    ///
    /// let odd = Odd::new(U128::from(7_u8)).unwrap();
    /// assert_eq!(odd.into_inner(), U128::from(7_u8));
    /// ```
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> AsRef<T> for Odd<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> Deref for Odd<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Odd;
    use crate::FixedBigUint;

    #[test]
    fn new_rejects_zero_and_even_values_and_preserves_odd_values() {
        type U = FixedBigUint<1>;

        assert_eq!(Odd::new(U::zero()), None);
        assert_eq!(Odd::new(U::from(6_u8)), None);

        let value = U::from(7_u8);
        let odd = Odd::new(value).expect("seven is odd");
        assert_eq!(odd.as_ref(), &value);
        assert_eq!(*odd, value);
        assert_eq!(odd.into_inner(), value);
    }

    #[test]
    fn zero_width_values_are_rejected_without_indexing_a_limb() {
        assert_eq!(Odd::new(FixedBigUint::<0>::zero()), None);
    }
}
