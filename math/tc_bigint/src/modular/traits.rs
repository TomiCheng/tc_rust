//! Montgomery-domain contracts shared by the fixed and dynamic forms.

use core::ops::{Add, Mul, Sub};

use crate::Odd;

/// A Montgomery form with reusable parameters.
pub trait Monty:
    Clone
    + Eq
    + Sized
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
{
    /// The integer type obtained when leaving the Montgomery domain.
    type Integer;

    /// The precomputed parameters required by this representation.
    type Params: Clone;

    /// Creates parameters from an odd modulus; execution time may depend on the modulus.
    fn new_params_vartime(modulus: Odd<Self::Integer>) -> Self::Params;

    /// Converts an integer into the specified Montgomery domain.
    fn new(value: &Self::Integer, params: Self::Params) -> Self;

    /// Creates zero in the specified domain.
    fn zero(params: Self::Params) -> Self;

    /// Creates one in the specified domain.
    fn one(params: Self::Params) -> Self;

    /// Returns the precomputed parameters for this value.
    fn params(&self) -> &Self::Params;

    /// Returns the modulus of this value's domain.
    fn modulus(&self) -> &Self::Integer;

    /// Converts out of the Montgomery domain.
    fn retrieve(&self) -> Self::Integer;

    /// Squares the value within the same domain.
    fn square(&self) -> Self;

    /// Doubles the value within the same domain.
    fn double(&self) -> Self;

    /// Raises the value to an exponent of the associated integer type.
    fn pow(&self, exponent: &Self::Integer) -> Self;

    /// Returns the multiplicative inverse, or `None` if it does not exist.
    fn invert(&self) -> Option<Self>;
}

/// An association from an underlying integer to its Montgomery form.
pub trait MontyInteger: Sized {
    /// The Montgomery representation associated with this integer.
    type Monty: Monty<Integer = Self>;
}

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
