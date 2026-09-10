//! Wrapper which carries a checked non-zero invariant.

use core::ops::Deref;

use crate::Zero;

/// An integer value known not to be zero.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NonZero<T>(T);

#[cfg(feature = "alloc")]
impl NonZero<crate::PaddedBigUint> {
    /// 變動時間：只能用於公開值。非零時建立包裝，保留原本的寬度。
    ///
    /// 保留較早版本的專用入口；目前也能使用 [`Self::new`]。
    /// 沒有 CT 建構包裝的入口；秘密值的非零檢查請保留 [`crate::PaddedBigUint::ct_is_zero`]
    /// 回傳的 `Choice`，不要轉成會揭露零值的 `Option`。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::{NonZero, PaddedBigUint};
    ///
    /// let value = PaddedBigUint::from_be_bytes(&[7], 3).unwrap();
    /// let nonzero = NonZero::new_padded(value).unwrap();
    /// assert_eq!(nonzero.len(), 3);
    /// assert!(NonZero::new_padded(PaddedBigUint::zero_with_limbs(3)).is_none());
    /// ```
    pub fn new_padded(value: crate::PaddedBigUint) -> Option<Self> {
        (!value.is_zero()).then_some(Self(value))
    }

    /// CT：取出被包住的值，不掃描數值，也不改變寬度。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::{NonZero, PaddedBigUint};
    ///
    /// let value = PaddedBigUint::from_be_bytes(&[7], 3).unwrap();
    /// let nonzero = NonZero::new_padded(value.clone()).unwrap();
    /// let restored = nonzero.into_padded();
    /// assert_eq!(restored, value);
    /// assert_eq!(restored.len(), 3);
    /// ```
    pub fn into_padded(self) -> crate::PaddedBigUint {
        self.0
    }
}

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
