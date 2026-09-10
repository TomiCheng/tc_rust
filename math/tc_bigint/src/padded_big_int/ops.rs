//! 變動時間：只能用於公開值。以符號擴展對齊寬度，溢位時 panic。
use crate::{BigInt, One, PaddedBigInt, Pow, Square, Zero, Zeroize};

/// 變動時間：只能用於公開值。建立兩個同寬副本，不改動輸入。
pub(super) fn aligned(a: &PaddedBigInt, b: &PaddedBigInt) -> (PaddedBigInt, PaddedBigInt) {
    let width = a.len().max(b.len());
    (
        a.resize(width).expect("加寬不會溢位"),
        b.resize(width).expect("加寬不會溢位"),
    )
}

/// 變動時間：只能用於公開值。委派結果放回已知可容納的寬度。
pub(super) fn public_result(value: BigInt, width: usize) -> PaddedBigInt {
    PaddedBigInt::from_big_int(&value, width).expect("運算結果超出目的寬度")
}

// 每種所有權組合共用借用核心，賦值先算完才取代目的物件。
macro_rules! binary_operator {
    ($trait:ident, $method:ident, $assign:ident, $assign_method:ident, $core:path, $guidance:literal) => {
        /// 變動時間：只能用於公開值。結果寬度為兩邊的最大值。
        #[doc = $guidance]
        impl core::ops::$trait for PaddedBigInt {
            type Output = PaddedBigInt;
            /// 變動時間：只能用於公開值。
            #[doc = $guidance]
            fn $method(self, rhs: Self) -> Self::Output {
                $core(&self, &rhs)
            }
        }
        /// 變動時間：只能用於公開值。結果寬度為兩邊的最大值。
        #[doc = $guidance]
        impl core::ops::$trait<&PaddedBigInt> for PaddedBigInt {
            type Output = PaddedBigInt;
            /// 變動時間：只能用於公開值。
            #[doc = $guidance]
            fn $method(self, rhs: &PaddedBigInt) -> Self::Output {
                $core(&self, rhs)
            }
        }
        /// 變動時間：只能用於公開值。結果寬度為兩邊的最大值。
        #[doc = $guidance]
        impl core::ops::$trait<PaddedBigInt> for &PaddedBigInt {
            type Output = PaddedBigInt;
            /// 變動時間：只能用於公開值。
            #[doc = $guidance]
            fn $method(self, rhs: PaddedBigInt) -> Self::Output {
                $core(self, &rhs)
            }
        }
        /// 變動時間：只能用於公開值。結果寬度為兩邊的最大值。
        #[doc = $guidance]
        impl core::ops::$trait<&PaddedBigInt> for &PaddedBigInt {
            type Output = PaddedBigInt;
            /// 變動時間：只能用於公開值。
            #[doc = $guidance]
            fn $method(self, rhs: &PaddedBigInt) -> Self::Output {
                $core(self, rhs)
            }
        }
        /// 變動時間：只能用於公開值。目的寬度可加寬，失敗時保留原值。
        #[doc = $guidance]
        impl core::ops::$assign<PaddedBigInt> for PaddedBigInt {
            /// 變動時間：只能用於公開值。
            #[doc = $guidance]
            fn $assign_method(&mut self, rhs: PaddedBigInt) {
                *self = $core(self, &rhs);
            }
        }
        /// 變動時間：只能用於公開值。目的寬度可加寬，失敗時保留原值。
        #[doc = $guidance]
        impl core::ops::$assign<&PaddedBigInt> for PaddedBigInt {
            /// 變動時間：只能用於公開值。
            #[doc = $guidance]
            fn $assign_method(&mut self, rhs: &PaddedBigInt) {
                *self = $core(self, rhs);
            }
        }
    };
}
pub(super) use binary_operator;

fn add(a: &PaddedBigInt, b: &PaddedBigInt) -> PaddedBigInt {
    let (a, b) = aligned(a, b);
    let (out, overflow) = PaddedBigInt::add(&a, &b);
    assert!(!overflow, "attempted to add with overflow");
    out
}
fn sub(a: &PaddedBigInt, b: &PaddedBigInt) -> PaddedBigInt {
    let (a, b) = aligned(a, b);
    let (out, overflow) = PaddedBigInt::sub(&a, &b);
    assert!(!overflow, "attempted to subtract with overflow");
    out
}
fn mul(a: &PaddedBigInt, b: &PaddedBigInt) -> PaddedBigInt {
    let (a, b) = aligned(a, b);
    let (out, overflow) = a.mul_core(&b);
    assert!(!overflow, "attempted to multiply with overflow");
    out
}
binary_operator!(
    Add,
    add,
    AddAssign,
    add_assign,
    add,
    "秘密值請用 [`PaddedBigInt::add`]。"
);
binary_operator!(
    Sub,
    sub,
    SubAssign,
    sub_assign,
    sub,
    "秘密值請用 [`PaddedBigInt::sub`]。"
);
binary_operator!(
    Mul,
    mul,
    MulAssign,
    mul_assign,
    mul,
    "本型別不提供公有 CT 乘法。"
);

/// 變動時間：只能用於公開值。預設為零寬的零。
impl Default for PaddedBigInt {
    fn default() -> Self {
        Self::zero_with_limbs(0)
    }
}
/// 變動時間：只能用於公開值。`zero()` 建立零寬；`set_zero()` 保留既有寬度。
impl Zero for PaddedBigInt {
    fn zero() -> Self {
        Self::default()
    }
    /// CT：清除全部 limb，保留原寬度。
    fn set_zero(&mut self) {
        self.zeroize();
    }
    fn is_zero(&self) -> bool {
        PaddedBigInt::is_zero(self)
    }
}
/// 變動時間：只能用於公開值。一的建構寬度為一個 limb。
impl One for PaddedBigInt {
    fn one() -> Self {
        Self::from_be_bytes(&[1], 1).expect("一可放進一個 limb")
    }
    /// 變動時間：只能用於公開值。保留寬度，零寬無法容納一而 panic。
    fn set_one(&mut self) {
        *self = Self::one().resize(self.len()).expect("零寬不能容納一");
    }
}

/// 變動時間：只能用於公開值。保留底數寬度，溢位時 panic；不提供公有 CT 乘法。
impl Pow<u32> for &PaddedBigInt {
    type Output = PaddedBigInt;
    fn pow(self, mut exponent: u32) -> Self::Output {
        let mut base = self.clone();
        if exponent == 0 {
            return PaddedBigInt::one()
                .resize(self.len())
                .expect("attempted to exponentiate with overflow");
        }
        let mut result = PaddedBigInt::one().resize(self.len()).unwrap_or_default();
        while exponent != 0 {
            if exponent & 1 != 0 {
                result *= &base;
            }
            exponent >>= 1;
            if exponent != 0 {
                base = &base * &base;
            }
        }
        result
    }
}
/// 變動時間：只能用於公開值。保留底數寬度；不提供公有 CT 乘法。
impl Pow<u32> for PaddedBigInt {
    type Output = Self;
    fn pow(self, exponent: u32) -> Self {
        Pow::pow(&self, exponent)
    }
}
/// 變動時間：只能用於公開值。保留底數寬度；不提供公有 CT 乘法。
impl Pow<&u32> for PaddedBigInt {
    type Output = Self;
    fn pow(self, exponent: &u32) -> Self {
        Pow::pow(&self, *exponent)
    }
}
/// 變動時間：只能用於公開值。保留底數寬度；不提供公有 CT 乘法。
impl Pow<&u32> for &PaddedBigInt {
    type Output = PaddedBigInt;
    fn pow(self, exponent: &u32) -> Self::Output {
        Pow::pow(self, *exponent)
    }
}
/// 變動時間：只能用於公開值。平方保留寬度；本型別不提供公有 CT 乘法。
impl Square for PaddedBigInt {
    type Output = Self;
    fn square(&self) -> Self {
        self * self
    }
}
