//! 變動時間：只能用於公開值。各溢位策略以兩邊較大的寬度為界。
use super::ops::aligned;
use crate::{
    CheckedAdd, CheckedDiv, CheckedMul, CheckedRem, CheckedShl, CheckedShr, CheckedSub, Limb,
    OverflowingAdd, OverflowingMul, OverflowingSub, PaddedBigUint, SaturatingAdd, SaturatingMul,
    SaturatingSub, Word, WrappingAdd, WrappingMul, WrappingSub,
};

fn maximum(width: usize) -> PaddedBigUint {
    PaddedBigUint::from_limbs(alloc::vec![Limb::new(Word::MAX); width].into_boxed_slice())
}
macro_rules! policies {
    ($checked:ident, $check:ident, $overflowing:ident, $overflow:ident,
     $wrapping:ident, $wrap:ident, $saturating:ident, $saturate:ident, $core:expr, $bound:expr) => {
        /// 變動時間：只能用於公開值。溢位回 `None`，結果寬度為兩邊最大值。
        impl $checked for PaddedBigUint {
            fn $check(&self, rhs: &Self) -> Option<Self> {
                let (out, overflow) = self.$overflow(rhs);
                (!overflow).then_some(out)
            }
        }
        /// 變動時間：只能用於公開值。回傳環繞結果與溢位旗標，寬度為兩邊最大值。
        impl $overflowing for PaddedBigUint {
            fn $overflow(&self, rhs: &Self) -> (Self, bool) {
                let (a, b) = aligned(self, rhs);
                ($core)(&a, &b)
            }
        }
        /// 變動時間：只能用於公開值。按兩邊最大寬度環繞。
        impl $wrapping for PaddedBigUint {
            fn $wrap(&self, rhs: &Self) -> Self {
                self.$overflow(rhs).0
            }
        }
        /// 變動時間：只能用於公開值。飽和界限依兩邊最大寬度決定。
        impl $saturating for PaddedBigUint {
            fn $saturate(&self, rhs: &Self) -> Self {
                let (out, overflow) = self.$overflow(rhs);
                if overflow { ($bound)(out.len()) } else { out }
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
    PaddedBigUint::add,
    maximum
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
    PaddedBigUint::sub,
    PaddedBigUint::zero_with_limbs
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
    |a: &PaddedBigUint, b: &PaddedBigUint| {
        let (low, high) = a.mul_wide(b);
        (low, !high.is_zero())
    },
    maximum
);

/// 變動時間：只能用於公開值。除數零時回 `None`；結果寬度為兩邊最大值。
impl CheckedDiv for PaddedBigUint {
    fn checked_div(&self, rhs: &Self) -> Option<Self> {
        if rhs.is_zero() {
            None
        } else {
            Some(self / rhs)
        }
    }
}
/// 變動時間：只能用於公開值。除數零時回 `None`；結果寬度為兩邊最大值。
impl CheckedRem for PaddedBigUint {
    fn checked_rem(&self, rhs: &Self) -> Option<Self> {
        if rhs.is_zero() {
            None
        } else {
            Some(self % rhs)
        }
    }
}
/// 變動時間：只能用於公開值。位移量超寬或數值溢位時回 `None`；秘密值用 [`PaddedBigUint::shl`]。
impl CheckedShl for PaddedBigUint {
    fn checked_shl(&self, shift: u32) -> Option<Self> {
        if shift as usize >= self.len() * Word::BITS as usize {
            return None;
        }
        let (out, lost) = PaddedBigUint::shl(self, shift as usize);
        (!lost).then_some(out)
    }
}
/// 變動時間：只能用於公開值。位移量超寬時回 `None`；秘密值用 [`PaddedBigUint::shr`]。
impl CheckedShr for PaddedBigUint {
    fn checked_shr(&self, shift: u32) -> Option<Self> {
        if shift as usize >= self.len() * Word::BITS as usize {
            None
        } else {
            Some(PaddedBigUint::shr(self, shift as usize))
        }
    }
}
