//! Values represented in a reusable Montgomery domain.

use core::ops::{Add, Mul, Sub};

#[cfg(feature = "alloc")]
use super::mul::montgomery_mul;
use super::mul::{fixed_add_mod, fixed_montgomery_mul, fixed_sub_mod};
use super::params::FixedMontyParams;
#[cfg(feature = "alloc")]
use super::params::MontyParams;
use super::pow::fixed_montgomery_pow;
#[cfg(feature = "alloc")]
use super::pow::montgomery_pow;
#[cfg(feature = "alloc")]
use crate::BigUint;
use crate::FixedBigUint;
#[cfg(feature = "alloc")]
use crate::Limb;
#[cfg(feature = "alloc")]
use crate::arithmetic::div_rem;
use crate::arithmetic::{fixed_div_rem, fixed_is_one};
use crate::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Recovers an ordinary integer from an alternate arithmetic representation.
pub trait Retrieve {
    /// Recovered integer type.
    type Output;

    /// Returns the represented ordinary integer.
    ///
    /// ```
    /// use tc_bigint::{
    ///     Odd, U128,
    ///     modular::{FixedMontyForm, FixedMontyParams, Retrieve},
    /// };
    /// let params = FixedMontyParams::new(Odd::new(U128::from(101_u8)).unwrap());
    /// let value = FixedMontyForm::new(&U128::from(108_u8), params);
    /// assert_eq!(Retrieve::retrieve(&value), U128::from(7_u8));
    /// ```
    fn retrieve(&self) -> Self::Output;
}

/// A dynamically sized value in Montgomery form.
///
/// Values can be multiplied repeatedly without recomputing the constants in
/// [`MontyParams`]. The represented ordinary integer is recovered with
/// [`Self::retrieve`].
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MontyForm<T> {
    value: T,
    params: MontyParams<T>,
}

#[cfg(feature = "alloc")]
impl MontyForm<BigUint> {
    /// Reduces `value` and enters the Montgomery domain.
    ///
    /// ```
    /// use tc_bigint::{BigUint, Odd, modular::{MontyForm, MontyParams}};
    /// let params = MontyParams::new(Odd::new(BigUint::from(101_u8)).unwrap());
    /// let value = MontyForm::new(&BigUint::from(108_u8), params);
    /// assert_eq!(value.retrieve(), BigUint::from(7_u8));
    /// ```
    pub fn new(value: &BigUint, params: MontyParams<BigUint>) -> Self {
        let modulus = params.modulus();
        let reduced = div_rem(value.as_limbs(), modulus.as_limbs()).1;
        let value = BigUint::from_limbs(montgomery_mul(
            &reduced,
            params.r2().as_limbs(),
            modulus.as_limbs(),
            params.mod_neg_inv,
        ));
        Self { value, params }
    }

    /// 在指定 Montgomery domain 中建立零。
    pub fn zero(params: MontyParams<BigUint>) -> Self {
        Self {
            value: BigUint::default(),
            params,
        }
    }

    /// 在指定 Montgomery domain 中建立一。
    pub fn one(params: MontyParams<BigUint>) -> Self {
        Self {
            value: params.one().clone(),
            params,
        }
    }

    /// 回傳建立此值時使用的 Montgomery 參數。
    pub fn params(&self) -> &MontyParams<BigUint> {
        &self.params
    }

    /// 回傳此 Montgomery domain 的模數。
    pub fn modulus(&self) -> &BigUint {
        self.params.modulus()
    }

    /// Leaves the Montgomery domain and returns the least non-negative value.
    ///
    /// ```
    /// use tc_bigint::{BigUint, Odd, modular::{MontyForm, MontyParams}};
    /// let params = MontyParams::new(Odd::new(BigUint::from(101_u8)).unwrap());
    /// assert_eq!(MontyForm::new(&BigUint::from(7_u8), params).retrieve(), BigUint::from(7_u8));
    /// ```
    pub fn retrieve(&self) -> BigUint {
        if self.params.modulus().as_limbs() == [Limb(1)] {
            return BigUint::default();
        }
        BigUint::from_limbs(montgomery_mul(
            self.value.as_limbs(),
            &[Limb(1)],
            self.params.modulus().as_limbs(),
            self.params.mod_neg_inv,
        ))
    }

    /// Squares the value while remaining in the same Montgomery domain.
    ///
    /// ```
    /// use tc_bigint::{BigUint, Odd, modular::{MontyForm, MontyParams}};
    /// let params = MontyParams::new(Odd::new(BigUint::from(101_u8)).unwrap());
    /// let value = MontyForm::new(&BigUint::from(7_u8), params);
    /// assert_eq!(value.square().retrieve(), BigUint::from(49_u8));
    /// ```
    pub fn square(&self) -> Self {
        let value = BigUint::from_limbs(montgomery_mul(
            self.value.as_limbs(),
            self.value.as_limbs(),
            self.params.modulus().as_limbs(),
            self.params.mod_neg_inv,
        ));
        Self {
            value,
            params: self.params.clone(),
        }
    }

    /// 在相同 Montgomery domain 中計算兩倍。
    pub fn double(&self) -> Self {
        self + self
    }

    /// Raises the value to `exponent` while reusing the stored parameters.
    ///
    /// ```
    /// use tc_bigint::{BigUint, Odd, modular::{MontyForm, MontyParams}};
    /// let params = MontyParams::new(Odd::new(BigUint::from(101_u8)).unwrap());
    /// let value = MontyForm::new(&BigUint::from(7_u8), params);
    /// assert_eq!(value.pow(&BigUint::from(20_u8)).retrieve(), BigUint::from(84_u8));
    /// ```
    pub fn pow(&self, exponent: &BigUint) -> Self {
        let value = BigUint::from_limbs(montgomery_pow(
            self.value.as_limbs(),
            exponent.as_limbs(),
            self.params.modulus().as_limbs(),
            self.params.mod_neg_inv,
            self.params.one().as_limbs(),
        ));
        Self {
            value,
            params: self.params.clone(),
        }
    }

    /// 回傳乘法反元素；不存在時回傳 `None`。
    ///
    /// 此薄封裝只串接既有的離開 domain、整數模反元素與重新進入 domain 路徑。
    pub fn invert(&self) -> Option<Self> {
        let inverse = self.retrieve().mod_inverse(self.modulus())?;
        Some(Self::new(&inverse, self.params.clone()))
    }

    fn add_ref(&self, rhs: &Self) -> Self {
        self.assert_same_params(rhs);
        let modulus = self.params.modulus();
        let distance = modulus - &rhs.value;
        let value = if self.value >= distance {
            &self.value - distance
        } else {
            &self.value + &rhs.value
        };
        Self {
            value,
            params: self.params.clone(),
        }
    }

    fn sub_ref(&self, rhs: &Self) -> Self {
        self.assert_same_params(rhs);
        let value = if self.value >= rhs.value {
            &self.value - &rhs.value
        } else {
            self.params.modulus() - (&rhs.value - &self.value)
        };
        Self {
            value,
            params: self.params.clone(),
        }
    }

    fn mul_ref(&self, rhs: &Self) -> Self {
        self.assert_same_params(rhs);
        let value = BigUint::from_limbs(montgomery_mul(
            self.value.as_limbs(),
            rhs.value.as_limbs(),
            self.params.modulus().as_limbs(),
            self.params.mod_neg_inv,
        ));
        Self {
            value,
            params: self.params.clone(),
        }
    }

    fn assert_same_params(&self, rhs: &Self) {
        assert!(
            self.params == rhs.params,
            "Montgomery forms use different moduli"
        );
    }
}

#[cfg(feature = "alloc")]
impl Retrieve for MontyForm<BigUint> {
    type Output = BigUint;

    fn retrieve(&self) -> Self::Output {
        MontyForm::retrieve(self)
    }
}

/// An allocation-free fixed-width value in Montgomery form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedMontyForm<const N: usize> {
    value: FixedBigUint<N>,
    params: FixedMontyParams<N>,
}

impl<const N: usize> FixedMontyForm<N> {
    /// Reduces a secret fixed-width integer with a fixed schedule and enters
    /// the public Montgomery domain. Unlike `new`, this does not use division.
    pub fn new_ct(value: &FixedBigUint<N>, params: FixedMontyParams<N>) -> Self {
        let mut result = Self::zero(params);
        let one = Self::one(params);
        for limb in value.as_limbs().iter().rev() {
            for bit in (0..crate::Word::BITS).rev() {
                result = result.double();
                let incremented = result + one;
                result = Self::conditional_select(
                    &result,
                    &incremented,
                    Choice::from_lsb((limb.0 >> bit) as u8),
                );
            }
        }
        result
    }
    /// Reduces `value` and enters the Montgomery domain without allocating.
    ///
    /// ```
    /// use tc_bigint::{Odd, U128, modular::{FixedMontyForm, FixedMontyParams}};
    /// let params = FixedMontyParams::new(Odd::new(U128::from(101_u8)).unwrap());
    /// let value = FixedMontyForm::new(&U128::from(108_u8), params);
    /// assert_eq!(value.retrieve(), U128::from(7_u8));
    /// ```
    pub fn new(value: &FixedBigUint<N>, params: FixedMontyParams<N>) -> Self {
        let modulus = params.modulus().as_limbs();
        let reduced = fixed_div_rem(value.as_limbs(), modulus).1;
        let value = fixed_montgomery_mul(
            &reduced,
            params.r2().as_limbs(),
            modulus,
            params.mod_neg_inv,
        );
        Self {
            value: FixedBigUint::from_limbs(value),
            params,
        }
    }

    /// 在指定 Montgomery domain 中建立零。
    pub fn zero(params: FixedMontyParams<N>) -> Self {
        Self {
            value: FixedBigUint::zero(),
            params,
        }
    }

    /// 在指定 Montgomery domain 中建立一。
    pub fn one(params: FixedMontyParams<N>) -> Self {
        Self {
            value: *params.one(),
            params,
        }
    }

    /// 回傳建立此值時使用的 Montgomery 參數。
    pub fn params(&self) -> &FixedMontyParams<N> {
        &self.params
    }

    /// 回傳此 Montgomery domain 的模數。
    pub fn modulus(&self) -> &FixedBigUint<N> {
        self.params.modulus()
    }

    /// Leaves the Montgomery domain and returns the least non-negative value.
    ///
    /// ```
    /// use tc_bigint::{Odd, U128, modular::{FixedMontyForm, FixedMontyParams}};
    /// let params = FixedMontyParams::new(Odd::new(U128::from(101_u8)).unwrap());
    /// assert_eq!(FixedMontyForm::new(&U128::from(7_u8), params).retrieve(), U128::from(7_u8));
    /// ```
    pub fn retrieve(&self) -> FixedBigUint<N> {
        let modulus = self.params.modulus().as_limbs();
        if fixed_is_one(modulus) {
            return FixedBigUint::zero();
        }
        let one = FixedBigUint::<N>::from(1_u8);
        FixedBigUint::from_limbs(fixed_montgomery_mul(
            self.value.as_limbs(),
            one.as_limbs(),
            modulus,
            self.params.mod_neg_inv,
        ))
    }

    /// Squares the value while remaining in the same Montgomery domain.
    ///
    /// ```
    /// use tc_bigint::{Odd, U128, modular::{FixedMontyForm, FixedMontyParams}};
    /// let params = FixedMontyParams::new(Odd::new(U128::from(101_u8)).unwrap());
    /// let value = FixedMontyForm::new(&U128::from(7_u8), params);
    /// assert_eq!(value.square().retrieve(), U128::from(49_u8));
    /// ```
    pub fn square(&self) -> Self {
        let value = fixed_montgomery_mul(
            self.value.as_limbs(),
            self.value.as_limbs(),
            self.params.modulus().as_limbs(),
            self.params.mod_neg_inv,
        );
        Self {
            value: FixedBigUint::from_limbs(value),
            params: self.params,
        }
    }

    /// 在相同 Montgomery domain 中計算兩倍。
    pub fn double(&self) -> Self {
        self + self
    }

    /// Raises the value to `exponent` while reusing the stored parameters.
    ///
    /// ```
    /// use tc_bigint::{Odd, U128, modular::{FixedMontyForm, FixedMontyParams}};
    /// let params = FixedMontyParams::new(Odd::new(U128::from(101_u8)).unwrap());
    /// let value = FixedMontyForm::new(&U128::from(7_u8), params);
    /// assert_eq!(value.pow(&U128::from(20_u8)).retrieve(), U128::from(84_u8));
    /// ```
    pub fn pow(&self, exponent: &FixedBigUint<N>) -> Self {
        let value = fixed_montgomery_pow(
            self.value.as_limbs(),
            exponent.as_limbs(),
            self.params.modulus().as_limbs(),
            self.params.mod_neg_inv,
            self.params.one().as_limbs(),
        );
        Self {
            value: FixedBigUint::from_limbs(value),
            params: self.params,
        }
    }

    /// 回傳乘法反元素；不存在時回傳 `None`。
    ///
    /// 此薄封裝只串接既有的離開 domain、整數模反元素與重新進入 domain 路徑。
    pub fn invert(&self) -> Option<Self> {
        let inverse = self.retrieve().mod_inverse(self.modulus())?;
        Some(Self::new(&inverse, self.params))
    }

    fn add_ref(&self, rhs: &Self) -> Self {
        self.assert_same_params(rhs);
        let value = fixed_add_mod(
            self.value.as_limbs(),
            rhs.value.as_limbs(),
            self.params.modulus().as_limbs(),
        );
        Self {
            value: FixedBigUint::from_limbs(value),
            params: self.params,
        }
    }

    fn sub_ref(&self, rhs: &Self) -> Self {
        self.assert_same_params(rhs);
        let value = fixed_sub_mod(
            self.value.as_limbs(),
            rhs.value.as_limbs(),
            self.params.modulus().as_limbs(),
        );
        Self {
            value: FixedBigUint::from_limbs(value),
            params: self.params,
        }
    }

    fn mul_ref(&self, rhs: &Self) -> Self {
        self.assert_same_params(rhs);
        let value = fixed_montgomery_mul(
            self.value.as_limbs(),
            rhs.value.as_limbs(),
            self.params.modulus().as_limbs(),
            self.params.mod_neg_inv,
        );
        Self {
            value: FixedBigUint::from_limbs(value),
            params: self.params,
        }
    }

    fn assert_same_params(&self, rhs: &Self) {
        assert!(
            self.params == rhs.params,
            "Montgomery forms use different moduli"
        );
    }
}

impl<const N: usize> Retrieve for FixedMontyForm<N> {
    type Output = FixedBigUint<N>;

    fn retrieve(&self) -> Self::Output {
        FixedMontyForm::retrieve(self)
    }
}

impl<const N: usize> ConditionallySelectable for FixedMontyForm<N> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        a.assert_same_params(b); // Domain parameters are public.
        Self {
            value: FixedBigUint::conditional_select(&a.value, &b.value, choice),
            params: a.params,
        }
    }
}
impl<const N: usize> ConstantTimeEq for FixedMontyForm<N> {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.assert_same_params(rhs);
        self.value.ct_eq(&rhs.value)
    }
}

impl<const N: usize> FixedMontyForm<N> {
    /// Fixed-schedule exponentiation over every bit of the fixed-width exponent.
    /// Modulus and limb count are public. Unlike `pow`, exponent bits are secret.
    pub fn pow_ct(&self, exponent: &FixedBigUint<N>) -> Self {
        let mut result = Self::one(self.params);
        for limb in exponent.as_limbs().iter().rev() {
            for bit in (0..crate::Word::BITS).rev() {
                result = result.square();
                let multiplied = result * self;
                result = Self::conditional_select(
                    &result,
                    &multiplied,
                    Choice::from_lsb((limb.0 >> bit) as u8),
                );
            }
        }
        result
    }
}

#[cfg(feature = "alloc")]
macro_rules! impl_monty_operators {
    ($form:ty) => {
        impl Add for $form {
            type Output = Self;
            fn add(self, rhs: Self) -> Self::Output {
                self.add_ref(&rhs)
            }
        }

        impl Add<&Self> for $form {
            type Output = Self;
            fn add(self, rhs: &Self) -> Self::Output {
                self.add_ref(rhs)
            }
        }

        impl Add<$form> for &$form {
            type Output = $form;
            fn add(self, rhs: $form) -> Self::Output {
                self.add_ref(&rhs)
            }
        }

        impl Add for &$form {
            type Output = $form;
            fn add(self, rhs: Self) -> Self::Output {
                self.add_ref(rhs)
            }
        }

        impl Sub for $form {
            type Output = Self;
            fn sub(self, rhs: Self) -> Self::Output {
                self.sub_ref(&rhs)
            }
        }

        impl Sub<&Self> for $form {
            type Output = Self;
            fn sub(self, rhs: &Self) -> Self::Output {
                self.sub_ref(rhs)
            }
        }

        impl Sub<$form> for &$form {
            type Output = $form;
            fn sub(self, rhs: $form) -> Self::Output {
                self.sub_ref(&rhs)
            }
        }

        impl Sub for &$form {
            type Output = $form;
            fn sub(self, rhs: Self) -> Self::Output {
                self.sub_ref(rhs)
            }
        }

        impl Mul for $form {
            type Output = Self;
            fn mul(self, rhs: Self) -> Self::Output {
                self.mul_ref(&rhs)
            }
        }

        impl Mul<&Self> for $form {
            type Output = Self;
            fn mul(self, rhs: &Self) -> Self::Output {
                self.mul_ref(rhs)
            }
        }

        impl Mul<$form> for &$form {
            type Output = $form;
            fn mul(self, rhs: $form) -> Self::Output {
                self.mul_ref(&rhs)
            }
        }

        impl Mul for &$form {
            type Output = $form;
            fn mul(self, rhs: Self) -> Self::Output {
                self.mul_ref(rhs)
            }
        }
    };
}

#[cfg(feature = "alloc")]
impl_monty_operators!(MontyForm<BigUint>);

impl<const N: usize> Add for FixedMontyForm<N> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        self.add_ref(&rhs)
    }
}
impl<const N: usize> Add<&Self> for FixedMontyForm<N> {
    type Output = Self;
    fn add(self, rhs: &Self) -> Self::Output {
        self.add_ref(rhs)
    }
}
impl<const N: usize> Add<FixedMontyForm<N>> for &FixedMontyForm<N> {
    type Output = FixedMontyForm<N>;
    fn add(self, rhs: FixedMontyForm<N>) -> Self::Output {
        self.add_ref(&rhs)
    }
}
impl<const N: usize> Add for &FixedMontyForm<N> {
    type Output = FixedMontyForm<N>;
    fn add(self, rhs: Self) -> Self::Output {
        self.add_ref(rhs)
    }
}
impl<const N: usize> Sub for FixedMontyForm<N> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self.sub_ref(&rhs)
    }
}
impl<const N: usize> Sub<&Self> for FixedMontyForm<N> {
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self::Output {
        self.sub_ref(rhs)
    }
}
impl<const N: usize> Sub<FixedMontyForm<N>> for &FixedMontyForm<N> {
    type Output = FixedMontyForm<N>;
    fn sub(self, rhs: FixedMontyForm<N>) -> Self::Output {
        self.sub_ref(&rhs)
    }
}
impl<const N: usize> Sub for &FixedMontyForm<N> {
    type Output = FixedMontyForm<N>;
    fn sub(self, rhs: Self) -> Self::Output {
        self.sub_ref(rhs)
    }
}
impl<const N: usize> Mul for FixedMontyForm<N> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        self.mul_ref(&rhs)
    }
}
impl<const N: usize> Mul<&Self> for FixedMontyForm<N> {
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self::Output {
        self.mul_ref(rhs)
    }
}
impl<const N: usize> Mul<FixedMontyForm<N>> for &FixedMontyForm<N> {
    type Output = FixedMontyForm<N>;
    fn mul(self, rhs: FixedMontyForm<N>) -> Self::Output {
        self.mul_ref(&rhs)
    }
}
impl<const N: usize> Mul for &FixedMontyForm<N> {
    type Output = FixedMontyForm<N>;
    fn mul(self, rhs: Self) -> Self::Output {
        self.mul_ref(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Odd, U128};

    #[test]
    fn fixed_form_reuses_parameters_for_arithmetic_and_power() {
        let params = FixedMontyParams::new(Odd::new(U128::from(101_u8)).unwrap());
        let seven = FixedMontyForm::new(&U128::from(7_u8), params);
        let nine = FixedMontyForm::new(&U128::from(9_u8), params);

        assert_eq!((seven + nine).retrieve(), U128::from(16_u8));
        assert_eq!((seven - nine).retrieve(), U128::from(99_u8));
        assert_eq!((seven * nine).retrieve(), U128::from(63_u8));
        assert_eq!(seven.square().retrieve(), U128::from(49_u8));
        assert_eq!(seven.pow(&U128::from(20_u8)).retrieve(), U128::from(84_u8));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_parameters_are_reused_across_one_hundred_powers() {
        let params = MontyParams::new(Odd::new(BigUint::from(101_u8)).unwrap());
        for exponent in 0_u8..100 {
            let value = MontyForm::new(&BigUint::from(7_u8), params.clone())
                .pow(&BigUint::from(exponent))
                .retrieve();
            assert_eq!(
                value,
                BigUint::from(7_u8).mod_pow(&BigUint::from(exponent), &BigUint::from(101_u8))
            );
        }
    }
}
