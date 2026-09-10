//! 變動時間：只能用於公開值。二元位元運算補零到較寬的一邊；位移保留左側寬度。
//! 零寬是合法的零：`<<`／`>>` 及其賦值形式對任何位移量都保留零寬，不 panic。
use super::ops::{aligned, binary_operator};
use crate::{AndNot, Limb, PaddedBigUint, Word};

fn map(a: &PaddedBigUint, b: &PaddedBigUint, f: fn(Word, Word) -> Word) -> PaddedBigUint {
    let (mut a, b) = aligned(a, b);
    for (left, right) in a.as_limbs_mut().iter_mut().zip(b.as_limbs()) {
        *left = Limb::new(f(left.to_word(), right.to_word()));
    }
    a
}
fn and(a: &PaddedBigUint, b: &PaddedBigUint) -> PaddedBigUint {
    map(a, b, |a, b| a & b)
}
fn or(a: &PaddedBigUint, b: &PaddedBigUint) -> PaddedBigUint {
    map(a, b, |a, b| a | b)
}
fn xor(a: &PaddedBigUint, b: &PaddedBigUint) -> PaddedBigUint {
    map(a, b, |a, b| a ^ b)
}
binary_operator!(
    BitAnd,
    bitand,
    BitAndAssign,
    bitand_assign,
    and,
    "沒有對應的具名 CT 位元運算。"
);
binary_operator!(
    BitOr,
    bitor,
    BitOrAssign,
    bitor_assign,
    or,
    "沒有對應的具名 CT 位元運算。"
);
binary_operator!(
    BitXor,
    bitxor,
    BitXorAssign,
    bitxor_assign,
    xor,
    "沒有對應的具名 CT 位元運算。"
);

/// 變動時間：只能用於公開值。補零到兩邊較大的寬度，再清除右側為一的位元。
impl AndNot for PaddedBigUint {
    type Output = Self;
    fn and_not(&self, rhs: &Self) -> Self {
        map(self, rhs, |a, b| a & !b)
    }
}
/// 變動時間：只能用於公開值。反轉儲存寬度內的所有位元。
impl core::ops::Not for &PaddedBigUint {
    type Output = PaddedBigUint;
    fn not(self) -> Self::Output {
        let mut out = self.clone();
        for limb in out.as_limbs_mut() {
            *limb = Limb::new(!limb.to_word());
        }
        out
    }
}
/// 變動時間：只能用於公開值。反轉所有位元，保留寬度。
impl core::ops::Not for PaddedBigUint {
    type Output = Self;
    fn not(self) -> Self {
        !&self
    }
}

fn left(a: &PaddedBigUint, shift: usize) -> PaddedBigUint {
    if a.is_empty() {
        return a.clone();
    }
    assert!(
        shift < a.len() * Word::BITS as usize,
        "attempted to shift left with overflow"
    );
    // 與 FixedBigUint 的位移運算子一致：超出最高位的部分截斷。
    PaddedBigUint::shl(a, shift).0
}
fn right(a: &PaddedBigUint, shift: usize) -> PaddedBigUint {
    if a.is_empty() {
        return a.clone();
    }
    assert!(
        shift < a.len() * Word::BITS as usize,
        "attempted to shift right with overflow"
    );
    PaddedBigUint::shr(a, shift)
}
macro_rules! shift_operator {
    ($trait:ident, $method:ident, $assign:ident, $assign_method:ident, $core:ident, $doc:literal) => {
        /// 變動時間：只能用於公開值。保留左側寬度；零寬對任何位移量都回零寬零。
        /// 非零寬時，位移量大於等於儲存位元數才會 panic。
        #[doc = $doc]
        impl core::ops::$trait<usize> for PaddedBigUint {
            type Output = Self;
            /// 變動時間：只能用於公開值。
            #[doc = $doc]
            fn $method(self, shift: usize) -> Self {
                $core(&self, shift)
            }
        }
        /// 變動時間：只能用於公開值。保留左側寬度；零寬對任何位移量都回零寬零。
        /// 非零寬時，位移量大於等於儲存位元數才會 panic。
        #[doc = $doc]
        impl core::ops::$trait<usize> for &PaddedBigUint {
            type Output = PaddedBigUint;
            /// 變動時間：只能用於公開值。
            #[doc = $doc]
            fn $method(self, shift: usize) -> Self::Output {
                $core(self, shift)
            }
        }
        /// 變動時間：只能用於公開值。保留左側寬度，失敗時保留原值。
        /// 零寬對任何位移量都保持原值；非零寬時位移量大於等於儲存位元數會 panic。
        #[doc = $doc]
        impl core::ops::$assign<usize> for PaddedBigUint {
            /// 變動時間：只能用於公開值。
            #[doc = $doc]
            fn $assign_method(&mut self, shift: usize) {
                *self = $core(self, shift);
            }
        }
    };
}
shift_operator!(
    Shl,
    shl,
    ShlAssign,
    shl_assign,
    left,
    "移出的高位截斷；需檢查數值溢位請用 [`crate::CheckedShl`]，秘密值請用 [`PaddedBigUint::shl`]。"
);
shift_operator!(
    Shr,
    shr,
    ShrAssign,
    shr_assign,
    right,
    "秘密值請用 [`PaddedBigUint::shr`]。"
);
