//! 補齊寬度的 Montgomery 域元素。
//!
//! # 常數時間約定
//!
//! **公開**：模數、寬度、[`PaddedMontyParams`] 的全部內容。
//! **秘密**：[`PaddedMontyForm`] 持有的值，以及模冪的指數。
//!
//! 秘密路徑上不得依秘密值分支、不得依秘密值索引、不得依秘密值決定圈數，
//! 也不得提早返回。約簡一律走無分支的條件寫回，不是 `if`。

use core::fmt;
use core::ops::{Add, Mul, Sub};

use super::padded_mul::{add_mod, double_mod, double_mod_assign, montgomery_mul, sub_mod};
use super::traits::Retrieve;
use crate::{
    Choice, ConditionallySelectable, ConstantTimeEq, PaddedBigUint, Word, Zeroize, ZeroizeOnDrop,
};

pub use super::padded_params::PaddedMontyParams;

/// 一個位於 Montgomery 域的值，寬度等於模數寬度。
///
/// 參數是 owned 的（見 [`PaddedMontyParams`]），所以本型別不帶生命週期，
/// 可以直接存進結構，clone 也只複製值本身。
///
/// [`fmt::Debug`] 只輸出寬度，不輸出值，避免秘密進到記錄。
#[derive(Clone)]
pub struct PaddedMontyForm {
    value: PaddedBigUint,
    params: PaddedMontyParams,
}

impl PaddedMontyForm {
    /// CT：把秘密值約簡進 Montgomery 域，不使用除法。
    ///
    /// `value` 的寬度可以大於模數寬度 —— RSA 的中國剩餘定理就會拿模數兩倍寬的
    /// 輸入進半寬的域。圈數只由 `value` 的公開寬度決定，與數值無關。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::{PaddedMontyForm, PaddedMontyParams};
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = Odd::new(PaddedBigUint::from_be_bytes(&[101], 1).unwrap()).unwrap();
    /// let params = PaddedMontyParams::new(modulus);
    /// let value = PaddedBigUint::from_be_bytes(&[108], 1).unwrap();
    /// let form = PaddedMontyForm::new_ct(&value, params);
    /// assert_eq!(form.retrieve(), PaddedBigUint::from_be_bytes(&[7], 1).unwrap());
    /// ```
    pub fn new_ct(value: &PaddedBigUint, params: PaddedMontyParams) -> Self {
        let modulus = params.modulus();
        let one = params.plain_one();
        let mut reduced = PaddedBigUint::zero_with_limbs(modulus.len());

        // 由最高位往下的 Horner：每一步倍加，再依該位元決定要不要加一。
        // 整個迴圈都走原地運算，只有最後的模乘會配置。
        for bit in (0..value.len() * Word::BITS as usize).rev() {
            double_mod_assign(&mut reduced, modulus);
            let carry = reduced.conditional_add_assign(one, value.bit_choice(bit));
            reduced.conditional_sub_assign(modulus, carry);
        }

        // 乘上 R² 就從一般表示法進到 Montgomery 域。
        let value = montgomery_mul(&reduced, params.r2(), modulus, params.mod_neg_inv());
        Self { value, params }
    }

    /// 變動時間：**只能用於公開值**。用除法約簡後進入 Montgomery 域。
    ///
    /// 公鑰運算的模數、指數與輸入全是公開的，走這條比逐位元的
    /// [`Self::new_ct`] 快兩個數量級。用在秘密值上會洩漏它。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::{PaddedMontyForm, PaddedMontyParams};
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = Odd::new(PaddedBigUint::from_be_bytes(&[101], 1).unwrap()).unwrap();
    /// let params = PaddedMontyParams::new(modulus);
    /// let value = PaddedBigUint::from_be_bytes(&[108], 1).unwrap();
    /// assert_eq!(
    ///     PaddedMontyForm::new(&value, params).retrieve(),
    ///     PaddedBigUint::from_be_bytes(&[7], 1).unwrap()
    /// );
    /// ```
    pub fn new(value: &PaddedBigUint, params: PaddedMontyParams) -> Self {
        let modulus = params.modulus();
        let reduced = value.to_big_uint() % modulus.to_big_uint();
        let reduced = PaddedBigUint::from_big_uint(&reduced, modulus.len())
            .expect("a value reduced by the modulus fits the modulus width");

        let value = montgomery_mul(&reduced, params.r2(), modulus, params.mod_neg_inv());
        Self { value, params }
    }

    /// CT：Montgomery 域中的零。
    pub fn zero(params: PaddedMontyParams) -> Self {
        Self {
            value: PaddedBigUint::zero_with_limbs(params.len()),
            params,
        }
    }

    /// CT：Montgomery 域中的一。
    pub fn one(params: PaddedMontyParams) -> Self {
        Self {
            value: params.one().clone(),
            params,
        }
    }

    /// CT：離開 Montgomery 域，回到一般表示法。寬度等於模數寬度。
    pub fn retrieve(&self) -> PaddedBigUint {
        montgomery_mul(
            &self.value,
            self.params.plain_one(),
            self.params.modulus(),
            self.params.mod_neg_inv(),
        )
    }

    /// CT：`choice` 為一時原地換成 `other` 的值，為零時保持原值。不配置記憶體。
    ///
    /// # Panics
    ///
    /// 兩個值的模數不同時 panic。
    pub(super) fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        self.assert_same_params(other);
        self.value.conditional_assign(&other.value, choice);
    }

    /// 這個值所屬的參數。
    pub fn params(&self) -> &PaddedMontyParams {
        &self.params
    }

    /// CT：域內平方。
    pub fn square(&self) -> Self {
        self.multiply(self)
    }

    /// CT：域內加倍。
    pub fn double(&self) -> Self {
        Self {
            value: double_mod(&self.value, self.params.modulus()),
            params: self.params.clone(),
        }
    }

    /// CT：域內乘法。
    fn multiply(&self, rhs: &Self) -> Self {
        self.assert_same_params(rhs);
        Self {
            value: montgomery_mul(
                &self.value,
                &rhs.value,
                self.params.modulus(),
                self.params.mod_neg_inv(),
            ),
            params: self.params.clone(),
        }
    }

    /// CT：域內加法。
    fn plus(&self, rhs: &Self) -> Self {
        self.assert_same_params(rhs);
        Self {
            value: add_mod(&self.value, &rhs.value, self.params.modulus()),
            params: self.params.clone(),
        }
    }

    /// CT：域內減法。
    fn minus(&self, rhs: &Self) -> Self {
        self.assert_same_params(rhs);
        Self {
            value: sub_mod(&self.value, &rhs.value, self.params.modulus()),
            params: self.params.clone(),
        }
    }

    /// 兩個值的模數不同時 panic。模數是公開資訊。
    fn assert_same_params(&self, rhs: &Self) {
        assert!(
            self.params.compatible_with(&rhs.params),
            "Montgomery forms use different moduli"
        );
    }
}

macro_rules! forward_binop {
    ($trait:ident, $method:ident, $implementation:ident) => {
        impl $trait<&PaddedMontyForm> for &PaddedMontyForm {
            type Output = PaddedMontyForm;
            fn $method(self, rhs: &PaddedMontyForm) -> PaddedMontyForm {
                PaddedMontyForm::$implementation(self, rhs)
            }
        }

        impl $trait<PaddedMontyForm> for &PaddedMontyForm {
            type Output = PaddedMontyForm;
            fn $method(self, rhs: PaddedMontyForm) -> PaddedMontyForm {
                PaddedMontyForm::$implementation(self, &rhs)
            }
        }

        impl $trait<&PaddedMontyForm> for PaddedMontyForm {
            type Output = PaddedMontyForm;
            fn $method(self, rhs: &PaddedMontyForm) -> PaddedMontyForm {
                PaddedMontyForm::$implementation(&self, rhs)
            }
        }

        impl $trait<PaddedMontyForm> for PaddedMontyForm {
            type Output = PaddedMontyForm;
            fn $method(self, rhs: PaddedMontyForm) -> PaddedMontyForm {
                PaddedMontyForm::$implementation(&self, &rhs)
            }
        }
    };
}

forward_binop!(Add, add, plus);
forward_binop!(Sub, sub, minus);
forward_binop!(Mul, mul, multiply);

impl Retrieve for PaddedMontyForm {
    type Output = PaddedBigUint;

    fn retrieve(&self) -> Self::Output {
        PaddedMontyForm::retrieve(self)
    }
}

impl ConstantTimeEq for PaddedMontyForm {
    /// CT：排程只由模數寬度決定；模數不同時 panic。
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.assert_same_params(rhs);
        self.value.ct_eq(&rhs.value)
    }
}

impl ConditionallySelectable for PaddedMontyForm {
    /// CT：排程只由模數寬度決定；模數不同時 panic。
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        a.assert_same_params(b);
        Self {
            value: PaddedBigUint::conditional_select(&a.value, &b.value, choice),
            params: a.params.clone(),
        }
    }
}

/// 變動時間：只能用於公開值。比較域內表示法，模數不同時 panic。
impl PartialEq for PaddedMontyForm {
    fn eq(&self, rhs: &Self) -> bool {
        self.assert_same_params(rhs);
        self.value == rhs.value
    }
}

impl Eq for PaddedMontyForm {}

impl Zeroize for PaddedMontyForm {
    /// CT：清除域內表示法。參數是公開的，不需要清。
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

/// 值本身是 [`ZeroizeOnDrop`]，所以整個 form 離開作用域時就會被清除。
impl ZeroizeOnDrop for PaddedMontyForm {}

/// 只輸出寬度，不輸出值。
impl fmt::Debug for PaddedMontyForm {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("PaddedMontyForm")
            .field("limbs", &self.value.len())
            .finish_non_exhaustive()
    }
}
