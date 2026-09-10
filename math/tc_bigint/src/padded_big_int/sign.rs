//! 變動時間：只能用於公開值。有號數值分類。
use crate::{One, PaddedBigInt, Signed};

impl PaddedBigInt {
    /// 變動時間：只能用於公開值。回傳符號位，零寬回假；秘密值用 [`Self::ct_is_negative`]。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::PaddedBigInt;
    ///
    /// let value = PaddedBigInt::from_be_bytes(&[0xf9], 3).unwrap();
    /// assert!(value.is_negative());
    /// ```
    pub fn is_negative(&self) -> bool {
        self.sign_bit() != 0
    }

    /// 變動時間：只能用於公開值。依負、零、正回傳 -1、0、1。
    /// 秘密值請保留 [`Self::ct_is_negative`]／[`Self::ct_is_zero`] 的 `Choice`，不依符號分支。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::PaddedBigInt;
    ///
    /// let value = PaddedBigInt::from_be_bytes(&[0xf9], 3).unwrap();
    /// assert_eq!(value.sign(), -1);
    /// assert_eq!(PaddedBigInt::zero_with_limbs(0).sign(), 0);
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

    /// 變動時間：只能用於公開值。絕對值保留寬度，最小負值會 panic。
    /// 沒有直接對應的 CT 絕對值方法；秘密值應保留有號表示，勿呼叫本方法。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::PaddedBigInt;
    ///
    /// let value = PaddedBigInt::from_be_bytes(&[0xf9], 3).unwrap();
    /// let magnitude = value.abs();
    /// assert_eq!(magnitude.len(), 3);
    /// assert_eq!(magnitude, PaddedBigInt::from_be_bytes(&[7], 3).unwrap());
    /// ```
    pub fn abs(&self) -> Self {
        if self.is_negative() {
            -self
        } else {
            self.clone()
        }
    }
}
/// 變動時間：只能用於公開值。一元操作保留原寬，二元操作採兩邊最大寬度。
impl Signed for PaddedBigInt {
    fn abs(&self) -> Self {
        PaddedBigInt::abs(self)
    }
    fn abs_sub(&self, rhs: &Self) -> Self {
        if self <= rhs {
            Self::zero_with_limbs(self.len().max(rhs.len()))
        } else {
            self - rhs
        }
    }
    fn signum(&self) -> Self {
        if self.is_zero() {
            Self::zero_with_limbs(self.len())
        } else {
            let one = Self::one()
                .resize(self.len())
                .expect("非零值有符號儲存空間");
            if self.is_negative() { -one } else { one }
        }
    }
    fn is_positive(&self) -> bool {
        !self.is_negative() && !self.is_zero()
    }
    fn is_negative(&self) -> bool {
        PaddedBigInt::is_negative(self)
    }
}
