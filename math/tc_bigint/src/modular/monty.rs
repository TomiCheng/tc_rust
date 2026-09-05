//! Montgomery 形式與原始整數之間的泛型連結。
//!
//! 此介面沿用 RustCrypto `crypto-bigint` 的分層：演算法面向 Montgomery 形式，
//! 整數則以反向關聯型別指出對應表示。tc_bigint 使用一般 [`Option`] 回傳反元素，
//! 不為此抽象引入 `subtle`。

use core::ops::{Add, Mul, Sub};

#[cfg(feature = "alloc")]
use crate::BigUint;
use crate::{FixedBigUint, Odd};

use super::{FixedMontyForm, FixedMontyParams};
#[cfg(feature = "alloc")]
use super::{MontyForm, MontyParams};

/// 可重用參數的 Montgomery 形式。
pub trait Monty:
    Clone
    + Eq
    + Sized
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
{
    /// 離開 Montgomery domain 後的整數型別。
    type Integer;

    /// 此表示需要的預先計算參數。
    type Params: Clone;

    /// 由奇數模數建立參數；計算時間可依模數而變。
    fn new_params_vartime(modulus: Odd<Self::Integer>) -> Self::Params;

    /// 將整數轉入指定 Montgomery domain。
    fn new(value: &Self::Integer, params: Self::Params) -> Self;

    /// 建立指定 domain 的零。
    fn zero(params: Self::Params) -> Self;

    /// 建立指定 domain 的一。
    fn one(params: Self::Params) -> Self;

    /// 回傳此值的預先計算參數。
    fn params(&self) -> &Self::Params;

    /// 回傳此值所屬 domain 的模數。
    fn modulus(&self) -> &Self::Integer;

    /// 離開 Montgomery domain。
    fn retrieve(&self) -> Self::Integer;

    /// 平方並留在相同 domain。
    fn square(&self) -> Self;

    /// 加倍並留在相同 domain。
    fn double(&self) -> Self;

    /// 以同型別整數為指數做次方。
    fn pow(&self, exponent: &Self::Integer) -> Self;

    /// 回傳乘法反元素；不存在時回傳 `None`。
    fn invert(&self) -> Option<Self>;
}

/// 原始整數到其 Montgomery 形式的反向連結。
pub trait MontyInteger: Sized {
    /// 此整數對應的 Montgomery 表示。
    type Monty: Monty<Integer = Self>;
}

#[cfg(feature = "alloc")]
impl Monty for MontyForm<BigUint> {
    type Integer = BigUint;
    type Params = MontyParams<BigUint>;

    fn new_params_vartime(modulus: Odd<Self::Integer>) -> Self::Params {
        MontyParams::new(modulus)
    }

    fn new(value: &Self::Integer, params: Self::Params) -> Self {
        MontyForm::new(value, params)
    }

    fn zero(params: Self::Params) -> Self {
        MontyForm::zero(params)
    }

    fn one(params: Self::Params) -> Self {
        MontyForm::one(params)
    }

    fn params(&self) -> &Self::Params {
        MontyForm::params(self)
    }

    fn modulus(&self) -> &Self::Integer {
        MontyForm::modulus(self)
    }

    fn retrieve(&self) -> Self::Integer {
        MontyForm::retrieve(self)
    }

    fn square(&self) -> Self {
        MontyForm::square(self)
    }

    fn double(&self) -> Self {
        MontyForm::double(self)
    }

    fn pow(&self, exponent: &Self::Integer) -> Self {
        MontyForm::pow(self, exponent)
    }

    fn invert(&self) -> Option<Self> {
        MontyForm::invert(self)
    }
}

impl<const N: usize> Monty for FixedMontyForm<N> {
    type Integer = FixedBigUint<N>;
    type Params = FixedMontyParams<N>;

    fn new_params_vartime(modulus: Odd<Self::Integer>) -> Self::Params {
        FixedMontyParams::new(modulus)
    }

    fn new(value: &Self::Integer, params: Self::Params) -> Self {
        FixedMontyForm::new(value, params)
    }

    fn zero(params: Self::Params) -> Self {
        FixedMontyForm::zero(params)
    }

    fn one(params: Self::Params) -> Self {
        FixedMontyForm::one(params)
    }

    fn params(&self) -> &Self::Params {
        FixedMontyForm::params(self)
    }

    fn modulus(&self) -> &Self::Integer {
        FixedMontyForm::modulus(self)
    }

    fn retrieve(&self) -> Self::Integer {
        FixedMontyForm::retrieve(self)
    }

    fn square(&self) -> Self {
        FixedMontyForm::square(self)
    }

    fn double(&self) -> Self {
        FixedMontyForm::double(self)
    }

    fn pow(&self, exponent: &Self::Integer) -> Self {
        FixedMontyForm::pow(self, exponent)
    }

    fn invert(&self) -> Option<Self> {
        FixedMontyForm::invert(self)
    }
}

#[cfg(feature = "alloc")]
impl MontyInteger for BigUint {
    type Monty = MontyForm<Self>;
}

impl<const N: usize> MontyInteger for FixedBigUint<N> {
    type Monty = FixedMontyForm<N>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::U128;

    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_trait_forwards_to_inherent_methods() {
        type Form = MontyForm<BigUint>;

        let modulus = Odd::new(BigUint::from(101_u8)).unwrap();
        let params = <Form as Monty>::new_params_vartime(modulus);
        let value = BigUint::from(7_u8);
        let exponent = BigUint::from(20_u8);
        let form = <Form as Monty>::new(&value, params.clone());

        assert_eq!(
            <Form as Monty>::zero(params.clone()),
            Form::zero(params.clone())
        );
        assert_eq!(
            <Form as Monty>::one(params.clone()),
            Form::one(params.clone())
        );
        assert_eq!(<Form as Monty>::params(&form), form.params());
        assert_eq!(<Form as Monty>::modulus(&form), form.modulus());
        assert_eq!(<Form as Monty>::retrieve(&form), form.retrieve());
        assert_eq!(<Form as Monty>::square(&form), form.square());
        assert_eq!(<Form as Monty>::double(&form), form.double());
        assert_eq!(<Form as Monty>::pow(&form, &exponent), form.pow(&exponent));
        assert_eq!(<Form as Monty>::invert(&form), form.invert());
    }

    #[test]
    fn fixed_trait_forwards_to_inherent_methods() {
        type Form = FixedMontyForm<{ 128 / crate::Word::BITS as usize }>;

        let modulus = Odd::new(U128::from(101_u8)).unwrap();
        let params = <Form as Monty>::new_params_vartime(modulus);
        let value = U128::from(7_u8);
        let exponent = U128::from(20_u8);
        let form = <Form as Monty>::new(&value, params);

        assert_eq!(<Form as Monty>::zero(params), Form::zero(params));
        assert_eq!(<Form as Monty>::one(params), Form::one(params));
        assert_eq!(<Form as Monty>::params(&form), form.params());
        assert_eq!(<Form as Monty>::modulus(&form), form.modulus());
        assert_eq!(<Form as Monty>::retrieve(&form), form.retrieve());
        assert_eq!(<Form as Monty>::square(&form), form.square());
        assert_eq!(<Form as Monty>::double(&form), form.double());
        assert_eq!(<Form as Monty>::pow(&form, &exponent), form.pow(&exponent));
        assert_eq!(<Form as Monty>::invert(&form), form.invert());
    }
}
