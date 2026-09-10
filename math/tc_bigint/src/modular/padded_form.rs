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
/// 秘密輸入使用 [`Self::new_ct`]，秘密指數使用 [`Self::pow_ct`]；
/// [`Self::new`]／[`Self::pow`] 則分別只接受公開輸入／公開指數。
///
/// # Examples
///
/// ```
/// use tc_bigint::modular::{PaddedMontyForm, PaddedMontyParams};
/// use tc_bigint::{Odd, PaddedBigUint};
///
/// // form 持有參數，不需要讓結構帶借用生命週期。
/// struct Accumulator {
///     value: PaddedMontyForm,
/// }
/// let modulus = Odd::new(PaddedBigUint::from_be_bytes(&[101], 2).unwrap()).unwrap();
/// let accumulator = {
///     let params = PaddedMontyParams::new(modulus);
///     Accumulator { value: PaddedMontyForm::one(params) }
/// };
/// assert_eq!(accumulator.value.retrieve(), PaddedBigUint::from_be_bytes(&[1], 2).unwrap());
/// ```
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
    /// 若輸入已確定公開，可改用除法約簡的 [`Self::new`]。
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
    /// // 把 value 視為秘密輸入，選 new_ct；不能因測試值很小就改用 new。
    /// let form = PaddedMontyForm::new_ct(&value, params);
    /// assert_eq!(form.retrieve(), PaddedBigUint::from_be_bytes(&[7], 1).unwrap());
    /// ```
    pub fn new_ct(value: &PaddedBigUint, params: PaddedMontyParams) -> Self {
        // 兩條路的圈數都只由公開的寬度決定，這個分支不洩漏數值。
        let value = if value.len() <= 2 * params.len() {
            Self::split_into_domain(value, &params)
        } else {
            Self::reduce_by_horner(value, &params)
        };
        Self { value, params }
    }

    /// CT：輸入不寬於模數兩倍時，拆成高低兩段各自進域再相加。
    ///
    /// 記 `R` 為 `2^(N * Word::BITS)`，把輸入寫成 `lo + hi * R`，則它的
    /// Montgomery 表示法是 `lo * R + hi * R²`。三次模乘就能算出來：
    ///
    /// * `mont(lo, R²) = lo * R`
    /// * `mont(hi, R²) = hi * R`，再 `mont(hi * R, R²) = hi * R²`
    ///
    /// 取代逐位元的 [`reduce_by_horner`]：`2N * Word::BITS` 圈變成三次模乘。
    ///
    /// 兩段都可能大於等於模數，但 CIOS 只要求其中一個運算元小於模數，
    /// 而 `R²` 已經約簡過，所以結果仍落在 `[0, 2n)`，由模乘自己收回來。
    fn split_into_domain(value: &PaddedBigUint, params: &PaddedMontyParams) -> PaddedBigUint {
        let modulus = params.modulus();
        let inverse = params.mod_neg_inv();
        let r2 = params.r2();
        let width = modulus.len();

        let (low, high) = value.split_at(width);
        // 兩段都不寬於模數，所以只會補零，不會失敗。
        let low = low
            .resize(width)
            .expect("the low half is never wider than the modulus");
        let high = high
            .resize(width)
            .expect("the high half is never wider than the modulus");

        let low = montgomery_mul(&low, r2, modulus, inverse);
        let mut high = montgomery_mul(&high, r2, modulus, inverse);
        high = montgomery_mul(&high, r2, modulus, inverse);
        add_mod(&low, &high, modulus)
    }

    /// CT：逐位元的 Horner 約簡，圈數是 `value.len() * Word::BITS`。
    ///
    /// 只在輸入寬於模數兩倍時用得到 —— [`split_into_domain`] 需要那個上界。
    /// 整個迴圈走原地運算，不配置記憶體。
    fn reduce_by_horner(value: &PaddedBigUint, params: &PaddedMontyParams) -> PaddedBigUint {
        let modulus = params.modulus();
        let one = params.plain_one();
        let mut reduced = PaddedBigUint::zero_with_limbs(modulus.len());

        for bit in (0..value.len() * Word::BITS as usize).rev() {
            double_mod_assign(&mut reduced, modulus);
            let carry = reduced.conditional_add_assign(one, value.bit_choice(bit));
            reduced.conditional_sub_assign(modulus, carry);
        }

        // 乘上 R² 就從一般表示法進到 Montgomery 域。
        montgomery_mul(&reduced, params.r2(), modulus, params.mod_neg_inv())
    }

    /// 變動時間：**只能用於公開值**。用除法約簡後進入 Montgomery 域。
    ///
    /// 公開輸入可走這條除法約簡路徑；秘密值必須使用 [`Self::new_ct`]。
    /// 與逐位元約簡相比可快兩個數量級，但 `new_ct` 已對不超過模數兩倍寬的
    /// 輸入使用三次模乘，不能把該倍率視為所有輸入的保證。
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
    /// // 此處明確把 value 視為公開輸入，才選 new；秘密輸入改用 new_ct。
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
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::{PaddedMontyForm, PaddedMontyParams};
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = PaddedBigUint::from_be_bytes(&[101], 2).unwrap();
    /// let params = PaddedMontyParams::new(Odd::new(modulus.clone()).unwrap());
    /// let zero = PaddedMontyForm::zero(params);
    /// assert_eq!(zero.retrieve(), PaddedBigUint::zero_with_limbs(2));
    /// ```
    pub fn zero(params: PaddedMontyParams) -> Self {
        Self {
            value: PaddedBigUint::zero_with_limbs(params.len()),
            params,
        }
    }

    /// CT：Montgomery 域中的一。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::{PaddedMontyForm, PaddedMontyParams};
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = PaddedBigUint::from_be_bytes(&[101], 2).unwrap();
    /// let params = PaddedMontyParams::new(Odd::new(modulus.clone()).unwrap());
    /// let one = PaddedMontyForm::one(params);
    /// assert_eq!(one.retrieve(), PaddedBigUint::from_be_bytes(&[1], 2).unwrap());
    /// ```
    pub fn one(params: PaddedMontyParams) -> Self {
        Self {
            value: params.one().clone(),
            params,
        }
    }

    /// CT：離開 Montgomery 域，回到一般表示法。寬度等於模數寬度。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::{PaddedMontyForm, PaddedMontyParams};
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = PaddedBigUint::from_be_bytes(&[101], 2).unwrap();
    /// let params = PaddedMontyParams::new(Odd::new(modulus.clone()).unwrap());
    /// let input = PaddedBigUint::from_be_bytes(&[108], 4).unwrap();
    /// let form = PaddedMontyForm::new_ct(&input, params);
    /// let reduced = form.retrieve();
    /// assert_eq!(reduced.len(), 2);
    /// assert_eq!(reduced, PaddedBigUint::from_be_bytes(&[7], 2).unwrap());
    /// ```
    pub fn retrieve(&self) -> PaddedBigUint {
        montgomery_mul(
            &self.value,
            self.params.plain_one(),
            self.params.modulus(),
            self.params.mod_neg_inv(),
        )
    }

    /// CT：借出這個值所屬的公開參數，不掃描數值。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::{PaddedMontyForm, PaddedMontyParams};
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = PaddedBigUint::from_be_bytes(&[101], 2).unwrap();
    /// let params = PaddedMontyParams::new(Odd::new(modulus.clone()).unwrap());
    /// let one = PaddedMontyForm::one(params);
    /// let zero = PaddedMontyForm::zero(one.params().clone());
    /// assert_eq!(one.params().modulus(), &modulus);
    /// assert_eq!((&one + &zero).retrieve(), one.retrieve());
    /// ```
    pub fn params(&self) -> &PaddedMontyParams {
        &self.params
    }

    /// 域內的原始表示法，供同模組的模冪重複使用緩衝區。
    pub(super) fn as_value(&self) -> &PaddedBigUint {
        &self.value
    }

    /// 以既有參數包住一個域內表示法。
    pub(super) fn from_value(value: PaddedBigUint, params: PaddedMontyParams) -> Self {
        debug_assert_eq!(value.len(), params.len());
        Self { value, params }
    }

    /// CT：域內平方。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::{PaddedMontyForm, PaddedMontyParams};
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = PaddedBigUint::from_be_bytes(&[101], 2).unwrap();
    /// let params = PaddedMontyParams::new(Odd::new(modulus.clone()).unwrap());
    /// let value = PaddedBigUint::from_be_bytes(&[11], 2).unwrap();
    /// let form = PaddedMontyForm::new_ct(&value, params);
    /// // 11² mod 101 = 20。
    /// assert_eq!(form.square().retrieve(), PaddedBigUint::from_be_bytes(&[20], 2).unwrap());
    /// ```
    pub fn square(&self) -> Self {
        self.multiply(self)
    }

    /// CT：域內加倍。
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_bigint::modular::{PaddedMontyForm, PaddedMontyParams};
    /// use tc_bigint::{Odd, PaddedBigUint};
    ///
    /// let modulus = PaddedBigUint::from_be_bytes(&[101], 2).unwrap();
    /// let params = PaddedMontyParams::new(Odd::new(modulus.clone()).unwrap());
    /// let value = PaddedBigUint::from_be_bytes(&[60], 2).unwrap();
    /// let form = PaddedMontyForm::new_ct(&value, params);
    /// // 2 × 60 mod 101 = 19。
    /// assert_eq!(form.double().retrieve(), PaddedBigUint::from_be_bytes(&[19], 2).unwrap());
    /// ```
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
