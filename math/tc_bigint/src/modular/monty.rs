//! Generic links between Montgomery forms and their underlying integers.
//!
//! This interface follows the layering of RustCrypto `crypto-bigint`: algorithms operate on Montgomery forms,
//! while integers identify their representation through an associated type. tc_bigint returns inverses in an ordinary [`Option`],
//! without introducing a dependency on `subtle` for this abstraction.

#[cfg(feature = "alloc")]
use crate::BigUint;
use crate::{FixedBigUint, Odd};

use super::traits::{Monty, MontyInteger};

use super::{FixedMontyForm, FixedMontyParams};
#[cfg(feature = "alloc")]
use super::{MontyForm, MontyParams};

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

    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_inherent_helpers_satisfy_montgomery_properties() {
        type Form = MontyForm<BigUint>;

        let modulus = BigUint::from(101_u8);
        let params = MontyParams::new(Odd::new(modulus.clone()).unwrap());
        let form = Form::new(&BigUint::from(7_u8), params.clone());
        let zero = Form::zero(params.clone());
        let one = Form::one(params.clone());

        assert_eq!(zero.retrieve(), BigUint::from(0_u8));
        assert_eq!(one.retrieve(), BigUint::from(1_u8));
        assert_eq!(form.params(), &params);
        assert_eq!(form.modulus(), &modulus);

        let doubled = form.double();
        assert_eq!(doubled, form.clone() + &form);
        assert_eq!(doubled.retrieve(), BigUint::from(14_u8));

        let inverse = form.invert().expect("seven is invertible modulo 101");
        let product = form.clone() * &inverse;
        assert_eq!(product, one);
        assert_eq!(product.retrieve(), BigUint::from(1_u8));
        assert!(zero.invert().is_none());
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

    #[test]
    fn fixed_inherent_helpers_satisfy_montgomery_properties() {
        type Form = FixedMontyForm<{ 128 / crate::Word::BITS as usize }>;

        let modulus = U128::from(101_u8);
        let params = FixedMontyParams::new(Odd::new(modulus).unwrap());
        let form = Form::new(&U128::from(7_u8), params);
        let zero = Form::zero(params);
        let one = Form::one(params);

        assert_eq!(zero.retrieve(), U128::from(0_u8));
        assert_eq!(one.retrieve(), U128::from(1_u8));
        assert_eq!(form.params(), &params);
        assert_eq!(form.modulus(), &modulus);

        let doubled = form.double();
        assert_eq!(doubled, form + form);
        assert_eq!(doubled.retrieve(), U128::from(14_u8));

        let inverse = form.invert().expect("seven is invertible modulo 101");
        let product = form * inverse;
        assert_eq!(product, one);
        assert_eq!(product.retrieve(), U128::from(1_u8));
        assert!(zero.invert().is_none());
    }
}
