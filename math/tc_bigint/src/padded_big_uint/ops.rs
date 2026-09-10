//! 變動時間：只能用於公開值。運算子補到兩邊較大的寬度，溢位時 panic。
//! 秘密值改用同寬的 [`PaddedBigUint::add`]、[`PaddedBigUint::sub`]、
//! [`PaddedBigUint::mul_wide`]。
//! 若匯入同名的 `core::ops::Add`／`Sub` trait，Rust 的方法解析可能選到運算子；
//! CT 路徑可明寫 `PaddedBigUint::add(&a, &b)`／`PaddedBigUint::sub(&a, &b)` 消除歧義。
//!
//! # Examples
//! ```
//! use tc_bigint::{PaddedBigUint, Zero, One};
//! let a = PaddedBigUint::from_be_bytes(&[7], 4).unwrap();
//! let b = PaddedBigUint::from_be_bytes(&[7], 1).unwrap();
//! assert_eq!(a, b);
//! assert_ne!(a.len(), b.len());
//! let sum = &a + &b;
//! assert_eq!(sum.len(), 4);
//! assert_eq!(sum.to_big_uint(), 14_u8.into());
//! assert_eq!(&a + PaddedBigUint::zero(), a);
//! assert_eq!((&a + PaddedBigUint::one()).len(), 4);
//! // CT 方法要求同寬，回傳進位；公開值的 + 則在溢位時 panic。
//! let (sum, carry) = a.add(&b.resize(4).unwrap());
//! assert!(!carry);
//! assert_eq!(sum.len(), 4);
//! ```

use crate::{BigUint, One, PaddedBigUint, Pow, Square, Unsigned, Zero, Zeroize};

/// 變動時間：只能用於公開值。建立兩個同寬副本，不改動輸入。
pub(super) fn aligned(a: &PaddedBigUint, b: &PaddedBigUint) -> (PaddedBigUint, PaddedBigUint) {
    let width = a.len().max(b.len());
    (
        a.resize(width).expect("加寬不會溢位"),
        b.resize(width).expect("加寬不會溢位"),
    )
}

/// 變動時間：只能用於公開值。委派結果放回已知可容納的寬度。
pub(super) fn public_result(value: BigUint, width: usize) -> PaddedBigUint {
    PaddedBigUint::from_big_uint(&value, width).expect("運算結果超出目的寬度")
}

// 每種所有權組合共用借用核心，賦值先算完才取代目的物件。
macro_rules! binary_operator {
    ($trait:ident, $method:ident, $assign:ident, $assign_method:ident, $core:path, $guidance:literal) => {
        /// 變動時間：只能用於公開值。結果寬度為兩邊的最大值。
        #[doc = $guidance]
        impl core::ops::$trait for PaddedBigUint {
            type Output = PaddedBigUint;
            /// 變動時間：只能用於公開值。
            #[doc = $guidance]
            fn $method(self, rhs: Self) -> Self::Output {
                $core(&self, &rhs)
            }
        }
        /// 變動時間：只能用於公開值。結果寬度為兩邊的最大值。
        #[doc = $guidance]
        impl core::ops::$trait<&PaddedBigUint> for PaddedBigUint {
            type Output = PaddedBigUint;
            /// 變動時間：只能用於公開值。
            #[doc = $guidance]
            fn $method(self, rhs: &PaddedBigUint) -> Self::Output {
                $core(&self, rhs)
            }
        }
        /// 變動時間：只能用於公開值。結果寬度為兩邊的最大值。
        #[doc = $guidance]
        impl core::ops::$trait<PaddedBigUint> for &PaddedBigUint {
            type Output = PaddedBigUint;
            /// 變動時間：只能用於公開值。
            #[doc = $guidance]
            fn $method(self, rhs: PaddedBigUint) -> Self::Output {
                $core(self, &rhs)
            }
        }
        /// 變動時間：只能用於公開值。結果寬度為兩邊的最大值。
        #[doc = $guidance]
        impl core::ops::$trait<&PaddedBigUint> for &PaddedBigUint {
            type Output = PaddedBigUint;
            /// 變動時間：只能用於公開值。
            #[doc = $guidance]
            fn $method(self, rhs: &PaddedBigUint) -> Self::Output {
                $core(self, rhs)
            }
        }
        /// 變動時間：只能用於公開值。目的寬度可加寬，失敗時保留原值。
        #[doc = $guidance]
        impl core::ops::$assign<PaddedBigUint> for PaddedBigUint {
            /// 變動時間：只能用於公開值。
            #[doc = $guidance]
            fn $assign_method(&mut self, rhs: PaddedBigUint) {
                *self = $core(self, &rhs);
            }
        }
        /// 變動時間：只能用於公開值。目的寬度可加寬，失敗時保留原值。
        #[doc = $guidance]
        impl core::ops::$assign<&PaddedBigUint> for PaddedBigUint {
            /// 變動時間：只能用於公開值。
            #[doc = $guidance]
            fn $assign_method(&mut self, rhs: &PaddedBigUint) {
                *self = $core(self, rhs);
            }
        }
    };
}
pub(super) use binary_operator;

fn add(a: &PaddedBigUint, b: &PaddedBigUint) -> PaddedBigUint {
    let (a, b) = aligned(a, b);
    let (out, overflow) = PaddedBigUint::add(&a, &b);
    assert!(!overflow, "attempted to add with overflow");
    out
}
fn sub(a: &PaddedBigUint, b: &PaddedBigUint) -> PaddedBigUint {
    let (a, b) = aligned(a, b);
    let (out, overflow) = PaddedBigUint::sub(&a, &b);
    assert!(!overflow, "attempted to subtract with underflow");
    out
}
fn mul(a: &PaddedBigUint, b: &PaddedBigUint) -> PaddedBigUint {
    let (a, b) = aligned(a, b);
    let (out, high) = a.mul_wide(&b);
    assert!(high.is_zero(), "attempted to multiply with overflow");
    out
}
binary_operator!(
    Add,
    add,
    AddAssign,
    add_assign,
    add,
    "秘密值請用 [`PaddedBigUint::add`]。"
);
binary_operator!(
    Sub,
    sub,
    SubAssign,
    sub_assign,
    sub,
    "秘密值請用 [`PaddedBigUint::sub`]。"
);
binary_operator!(
    Mul,
    mul,
    MulAssign,
    mul_assign,
    mul,
    "秘密值請用 [`PaddedBigUint::mul_wide`]。"
);

/// 變動時間：只能用於公開值。預設為零寬的零。
impl Default for PaddedBigUint {
    fn default() -> Self {
        Self::zero_with_limbs(0)
    }
}
/// 變動時間：只能用於公開值。零的建構寬度為零。
impl Zero for PaddedBigUint {
    fn zero() -> Self {
        Self::default()
    }
    /// CT：清除全部 limb，保留原寬度。
    fn set_zero(&mut self) {
        self.zeroize();
    }
    fn is_zero(&self) -> bool {
        PaddedBigUint::is_zero(self)
    }
}
/// 變動時間：只能用於公開值。一的建構寬度為一個 limb。
impl One for PaddedBigUint {
    fn one() -> Self {
        Self::from_be_bytes(&[1], 1).expect("一可放進一個 limb")
    }
    /// 變動時間：只能用於公開值。保留寬度，零寬無法容納一而 panic。
    fn set_one(&mut self) {
        *self = Self::one().resize(self.len()).expect("零寬不能容納一");
    }
}
/// 變動時間：只能用於公開值。無號數值 trait 的標記。
impl Unsigned for PaddedBigUint {}

/// 變動時間：只能用於公開值。保留底數寬度，溢位時 panic；秘密乘法請用 [`PaddedBigUint::mul_wide`]。
impl Pow<u32> for &PaddedBigUint {
    type Output = PaddedBigUint;
    fn pow(self, mut exponent: u32) -> Self::Output {
        let mut base = self.clone();
        if exponent == 0 {
            return PaddedBigUint::one()
                .resize(self.len())
                .expect("attempted to exponentiate with overflow");
        }
        let mut result = PaddedBigUint::one().resize(self.len()).unwrap_or_default();
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
/// 變動時間：只能用於公開值。保留底數寬度；秘密乘法請用 [`PaddedBigUint::mul_wide`]。
impl Pow<u32> for PaddedBigUint {
    type Output = Self;
    fn pow(self, exponent: u32) -> Self {
        Pow::pow(&self, exponent)
    }
}
/// 變動時間：只能用於公開值。保留底數寬度；秘密乘法請用 [`PaddedBigUint::mul_wide`]。
impl Pow<&u32> for PaddedBigUint {
    type Output = Self;
    fn pow(self, exponent: &u32) -> Self {
        Pow::pow(&self, *exponent)
    }
}
/// 變動時間：只能用於公開值。保留底數寬度；秘密乘法請用 [`PaddedBigUint::mul_wide`]。
impl Pow<&u32> for &PaddedBigUint {
    type Output = PaddedBigUint;
    fn pow(self, exponent: &u32) -> Self::Output {
        Pow::pow(self, *exponent)
    }
}
/// 變動時間：只能用於公開值。平方保留寬度；秘密值請用 [`PaddedBigUint::mul_wide`]。
impl Square for PaddedBigUint {
    type Output = Self;
    fn square(&self) -> Self {
        self * self
    }
}
