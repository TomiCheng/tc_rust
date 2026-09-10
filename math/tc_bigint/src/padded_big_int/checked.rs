//! 變動時間：只能用於公開值。以對齊後的有號範圍處理溢位。
use super::ops::aligned;
use crate::{
    CheckedAdd, CheckedDiv, CheckedMul, CheckedRem, CheckedShl, CheckedShr, CheckedSub, Limb,
    OverflowingAdd, OverflowingMul, OverflowingSub, PaddedBigInt, SaturatingAdd, SaturatingMul,
    SaturatingSub, Word, WrappingAdd, WrappingMul, WrappingSub,
};

fn bound(width: usize, negative: bool) -> PaddedBigInt {
    let mut out = PaddedBigInt::zero_with_limbs(width);
    if width != 0 {
        if negative {
            out.limbs[width - 1] = Limb::new(1 << (Word::BITS - 1));
        } else {
            out.limbs.fill(Limb::new(Word::MAX));
            out.limbs[width - 1] = Limb::new(Word::MAX >> 1);
        }
    }
    out
}
macro_rules! policies {
    ($checked:ident, $check:ident, $overflowing:ident, $overflow:ident,
     $wrapping:ident, $wrap:ident, $saturating:ident, $saturate:ident, $core:path, $negative:expr) => {
        /// 變動時間：只能用於公開值。對齊最大寬度，有號溢位回 `None`。
        impl $checked for PaddedBigInt {
            fn $check(&self, rhs: &Self) -> Option<Self> {
                let (out, overflow) = self.$overflow(rhs);
                (!overflow).then_some(out)
            }
        }
        /// 變動時間：只能用於公開值。回傳最大寬度的環繞結果與有號溢位旗標。
        impl $overflowing for PaddedBigInt {
            fn $overflow(&self, rhs: &Self) -> (Self, bool) {
                let (a, b) = aligned(self, rhs);
                $core(&a, &b)
            }
        }
        /// 變動時間：只能用於公開值。依最大寬度環繞。
        impl $wrapping for PaddedBigInt {
            fn $wrap(&self, rhs: &Self) -> Self {
                self.$overflow(rhs).0
            }
        }
        /// 變動時間：只能用於公開值。飽和到最大寬度的有號上下界。
        impl $saturating for PaddedBigInt {
            fn $saturate(&self, rhs: &Self) -> Self {
                let (out, overflow) = self.$overflow(rhs);
                if overflow {
                    bound(out.len(), ($negative)(self, rhs))
                } else {
                    out
                }
            }
        }
    };
}
policies!(
    CheckedAdd,
    checked_add,
    OverflowingAdd,
    overflowing_add,
    WrappingAdd,
    wrapping_add,
    SaturatingAdd,
    saturating_add,
    PaddedBigInt::add,
    |a: &PaddedBigInt, _: &PaddedBigInt| a.is_negative()
);
policies!(
    CheckedSub,
    checked_sub,
    OverflowingSub,
    overflowing_sub,
    WrappingSub,
    wrapping_sub,
    SaturatingSub,
    saturating_sub,
    PaddedBigInt::sub,
    |a: &PaddedBigInt, _: &PaddedBigInt| a.is_negative()
);
policies!(
    CheckedMul,
    checked_mul,
    OverflowingMul,
    overflowing_mul,
    WrappingMul,
    wrapping_mul,
    SaturatingMul,
    saturating_mul,
    PaddedBigInt::mul_core,
    |a: &PaddedBigInt, b: &PaddedBigInt| a.is_negative() != b.is_negative()
);

/// 變動時間：只能用於公開值。除零或商超出最大寬度（包含 MIN / -1）回 `None`。
impl CheckedDiv for PaddedBigInt {
    fn checked_div(&self, rhs: &Self) -> Option<Self> {
        if rhs.is_zero() {
            return None;
        }
        Self::from_big_int(
            &(self.to_big_int() / rhs.to_big_int()),
            self.len().max(rhs.len()),
        )
        .ok()
    }
}
/// 變動時間：只能用於公開值。除零回 `None`，餘數保留兩邊最大寬度。
impl CheckedRem for PaddedBigInt {
    fn checked_rem(&self, rhs: &Self) -> Option<Self> {
        if rhs.is_zero() {
            return None;
        }
        Self::from_big_int(
            &(self.to_big_int() % rhs.to_big_int()),
            self.len().max(rhs.len()),
        )
        .ok()
    }
}
/// 變動時間：只能用於公開值。位移量超寬或數值有號溢位回 `None`。
impl CheckedShl for PaddedBigInt {
    fn checked_shl(&self, shift: u32) -> Option<Self> {
        let shift = shift as usize;
        if shift >= self.len() * Word::BITS as usize {
            return None;
        }
        let out = self.shl_core(shift);
        (out.shr_core(shift) == *self).then_some(out)
    }
}
/// 變動時間：只能用於公開值。位移量超寬回 `None`，否則算術右移。
impl CheckedShr for PaddedBigInt {
    fn checked_shr(&self, shift: u32) -> Option<Self> {
        if shift as usize >= self.len() * Word::BITS as usize {
            None
        } else {
            Some(self.shr_core(shift as usize))
        }
    }
}
