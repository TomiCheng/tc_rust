//! 變動時間：只能用於公開值。有號反相的明確溢位策略。
use crate::{CheckedNeg, PaddedBigInt, WrappingNeg};

/// 變動時間：只能用於公開值。反相保留寬度，最小負值回 `None`。
impl CheckedNeg for PaddedBigInt {
    fn checked_neg(&self) -> Option<Self> {
        let (out, overflow) = Self::sub(&Self::zero_with_limbs(self.len()), self);
        (!overflow).then_some(out)
    }
}
/// 變動時間：只能用於公開值。反相按原寬環繞，最小負值保持原值。
impl WrappingNeg for PaddedBigInt {
    fn wrapping_neg(&self) -> Self {
        Self::sub(&Self::zero_with_limbs(self.len()), self).0
    }
}
/// 變動時間：只能用於公開值。保留寬度，最小負值反相會 panic。
impl core::ops::Neg for &PaddedBigInt {
    type Output = PaddedBigInt;
    fn neg(self) -> Self::Output {
        self.checked_neg()
            .expect("attempted to negate with overflow")
    }
}
/// 變動時間：只能用於公開值。保留寬度，最小負值反相會 panic。
impl core::ops::Neg for PaddedBigInt {
    type Output = Self;
    fn neg(self) -> Self {
        -&self
    }
}
