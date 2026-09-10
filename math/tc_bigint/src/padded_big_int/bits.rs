//! 變動時間：只能用於公開值。二元位元運算符號擴展到較寬的一邊；位移保留左側寬度。
//! 零寬是合法的零：`<<`／`>>` 及其賦值形式對任何位移量都保留零寬，不 panic。
use super::ops::{aligned, binary_operator};
use crate::{AndNot, BitOps, Limb, PaddedBigInt, Word};

/// 變動時間：只能用於公開值。計數排除符號擴展；取位元使用無限符號擴展。
/// 修改位元保留寬度，超出儲存範圍時 panic。
impl BitOps for PaddedBigInt {
    type Output = Self;
    fn bit_length(&self) -> usize {
        self.to_big_int().bit_length()
    }
    fn bit_count(&self) -> usize {
        self.to_big_int().bit_count()
    }
    fn test_bit(&self, index: usize) -> bool {
        let word = self
            .limbs
            .get(index / Word::BITS as usize)
            .map_or(self.sign_extension(), |limb| limb.to_word());
        (word >> (index % Word::BITS as usize)) & 1 != 0
    }
    fn set_bit(&self, index: usize) -> Self {
        self.map_bit(index, |a, b| a | b)
    }
    fn clear_bit(&self, index: usize) -> Self {
        self.map_bit(index, |a, b| a & !b)
    }
    fn flip_bit(&self, index: usize) -> Self {
        self.map_bit(index, |a, b| a ^ b)
    }
    fn lowest_set_bit(&self) -> Option<usize> {
        self.to_big_int().lowest_set_bit()
    }
}
impl PaddedBigInt {
    fn map_bit(&self, index: usize, operation: fn(Word, Word) -> Word) -> Self {
        assert!(
            index < self.len() * Word::BITS as usize,
            "bit index is outside the padded width"
        );
        let mut out = self.clone();
        let word = index / Word::BITS as usize;
        let mask = (1 as Word) << (index % Word::BITS as usize);
        out.limbs[word] = Limb::new(operation(out.limbs[word].to_word(), mask));
        out
    }
}

fn map(a: &PaddedBigInt, b: &PaddedBigInt, f: fn(Word, Word) -> Word) -> PaddedBigInt {
    let (mut a, b) = aligned(a, b);
    for (left, right) in a.limbs.iter_mut().zip(b.limbs.iter()) {
        *left = Limb::new(f(left.to_word(), right.to_word()));
    }
    a
}
fn and(a: &PaddedBigInt, b: &PaddedBigInt) -> PaddedBigInt {
    map(a, b, |a, b| a & b)
}
fn or(a: &PaddedBigInt, b: &PaddedBigInt) -> PaddedBigInt {
    map(a, b, |a, b| a | b)
}
fn xor(a: &PaddedBigInt, b: &PaddedBigInt) -> PaddedBigInt {
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

/// 變動時間：只能用於公開值。符號擴展到兩邊較大的寬度，再清除右側為一的位元。
impl AndNot for PaddedBigInt {
    type Output = Self;
    fn and_not(&self, rhs: &Self) -> Self {
        map(self, rhs, |a, b| a & !b)
    }
}
/// 變動時間：只能用於公開值。反轉儲存寬度內的所有位元。
impl core::ops::Not for &PaddedBigInt {
    type Output = PaddedBigInt;
    fn not(self) -> Self::Output {
        let mut out = self.clone();
        for limb in &mut out.limbs {
            *limb = Limb::new(!limb.to_word());
        }
        out
    }
}
/// 變動時間：只能用於公開值。反轉所有位元，保留寬度。
impl core::ops::Not for PaddedBigInt {
    type Output = Self;
    fn not(self) -> Self {
        !&self
    }
}

fn left(a: &PaddedBigInt, shift: usize) -> PaddedBigInt {
    if a.is_empty() {
        return a.clone();
    }
    assert!(
        shift < a.len() * Word::BITS as usize,
        "attempted to shift left with overflow"
    );
    // 與 FixedBigInt 的位移運算子一致：超出最高位的部分截斷。
    a.shl_core(shift)
}
fn right(a: &PaddedBigInt, shift: usize) -> PaddedBigInt {
    if a.is_empty() {
        return a.clone();
    }
    assert!(
        shift < a.len() * Word::BITS as usize,
        "attempted to shift right with overflow"
    );
    a.shr_core(shift)
}
macro_rules! shift_operator {
    ($trait:ident, $method:ident, $assign:ident, $assign_method:ident, $core:ident, $doc:literal) => {
        /// 變動時間：只能用於公開值。保留左側寬度；零寬對任何位移量都回零寬零。
        /// 非零寬時，位移量大於等於儲存位元數才會 panic。
        #[doc = $doc]
        impl core::ops::$trait<usize> for PaddedBigInt {
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
        impl core::ops::$trait<usize> for &PaddedBigInt {
            type Output = PaddedBigInt;
            /// 變動時間：只能用於公開值。
            #[doc = $doc]
            fn $method(self, shift: usize) -> Self::Output {
                $core(self, shift)
            }
        }
        /// 變動時間：只能用於公開值。保留左側寬度，失敗時保留原值。
        /// 零寬對任何位移量都保持原值；非零寬時位移量大於等於儲存位元數會 panic。
        #[doc = $doc]
        impl core::ops::$assign<usize> for PaddedBigInt {
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
    "移出的高位截斷；需檢查數值溢位請用 [`crate::CheckedShl`]；本型別不提供公有 CT 位移。"
);
shift_operator!(
    Shr,
    shr,
    ShrAssign,
    shr_assign,
    right,
    "算術右移：高位補符號位。"
);
