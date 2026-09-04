//! Wrapper which carries a checked non-zero invariant.

use core::ops::Deref;

use crate::Zero;

/// An integer value known not to be zero.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NonZero<T>(T);

impl<T: Zero> NonZero<T> {
    /// Creates a wrapper when `value` is non-zero.
    pub fn new(value: T) -> Option<Self> {
        (!value.is_zero()).then_some(Self(value))
    }

    /// Extracts the wrapped value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> AsRef<T> for NonZero<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> Deref for NonZero<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::NonZero;
    use crate::FixedBigUint;

    #[test]
    fn new_rejects_zero_and_preserves_non_zero_values() {
        type U = FixedBigUint<1>;

        assert_eq!(NonZero::new(U::zero()), None);

        let value = U::from(7_u8);
        let non_zero = NonZero::new(value).expect("seven is non-zero");
        assert_eq!(non_zero.as_ref(), &value);
        assert_eq!(*non_zero, value);
        assert_eq!(non_zero.into_inner(), value);
    }
}
