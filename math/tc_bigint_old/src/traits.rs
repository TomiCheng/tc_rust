//! Numeric traits used by `tc_bigint_old`.
//!
//! The contracts in this module are adapted from `num-traits` 0.2, but are
//! defined locally so `tc_bigint_old` does not depend on that crate. Consequently,
//! these traits are not type-compatible with traits from `num-traits`.

pub use core::ops::Add;

use core::ops::{Div, Mul, Neg, Rem, Sub};

use crate::{BigInt, ParseBigIntError};

/// A value with an additive identity.
pub trait Zero: Sized + Add<Self, Output = Self> {
    /// Returns the additive identity.
    fn zero() -> Self;

    /// Replaces this value with the additive identity.
    fn set_zero(&mut self) {
        *self = Self::zero();
    }

    /// Returns whether this value is the additive identity.
    fn is_zero(&self) -> bool;
}

/// A value with a multiplicative identity.
pub trait One: Sized + Mul<Self, Output = Self> {
    /// Returns the multiplicative identity.
    fn one() -> Self;

    /// Replaces this value with the multiplicative identity.
    fn set_one(&mut self) {
        *self = Self::one();
    }

    /// Returns whether this value is the multiplicative identity.
    fn is_one(&self) -> bool
    where
        Self: PartialEq,
    {
        self == &Self::one()
    }
}

/// The five basic numeric operators.
pub trait NumOps<Rhs = Self, Output = Self>:
    Add<Rhs, Output = Output>
    + Sub<Rhs, Output = Output>
    + Mul<Rhs, Output = Output>
    + Div<Rhs, Output = Output>
    + Rem<Rhs, Output = Output>
{
}

impl<T, Rhs, Output> NumOps<Rhs, Output> for T where
    T: Add<Rhs, Output = Output>
        + Sub<Rhs, Output = Output>
        + Mul<Rhs, Output = Output>
        + Div<Rhs, Output = Output>
        + Rem<Rhs, Output = Output>
{
}

/// Base contract for a numeric value.
pub trait Num: PartialEq + Zero + One + NumOps {
    /// Error returned by [`Num::from_str_radix`].
    type FromStrRadixErr;

    /// Parses a value using `radix`.
    fn from_str_radix(value: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr>;
}

/// Operations specific to signed values.
pub trait Signed: Sized + Num + Neg<Output = Self> {
    /// Returns the absolute value.
    fn abs(&self) -> Self;

    /// Returns `self - other` when positive, or zero otherwise.
    fn abs_sub(&self, other: &Self) -> Self;

    /// Returns `-1`, `0`, or `1` according to the sign.
    fn signum(&self) -> Self;

    /// Returns whether this value is greater than zero.
    fn is_positive(&self) -> bool;

    /// Returns whether this value is less than zero.
    fn is_negative(&self) -> bool;
}

/// Marker trait for numeric values which cannot be negative.
pub trait Unsigned: Num {}

/// Exponentiation with a caller-selected exponent type.
pub trait Pow<Rhs> {
    /// Result of exponentiation.
    type Output;

    /// Raises `self` to `rhs`.
    fn pow(self, rhs: Rhs) -> Self::Output;
}

/// Checked addition.
pub trait CheckedAdd: Sized + Add<Self, Output = Self> {
    /// Returns the sum, or `None` when it cannot be represented.
    fn checked_add(&self, rhs: &Self) -> Option<Self>;
}

/// Addition which reports whether the result overflowed.
pub trait OverflowingAdd: Sized + Add<Self, Output = Self> {
    /// Returns the sum and an overflow flag.
    fn overflowing_add(&self, rhs: &Self) -> (Self, bool);
}

/// Addition which wraps at the numeric bounds.
pub trait WrappingAdd: Sized + Add<Self, Output = Self> {
    /// Returns the wrapping sum.
    fn wrapping_add(&self, rhs: &Self) -> Self;
}

/// Addition which clamps at the numeric bounds.
pub trait SaturatingAdd: Sized + Add<Self, Output = Self> {
    /// Returns the saturating sum.
    fn saturating_add(&self, rhs: &Self) -> Self;
}

/// Conversion from primitive numeric types.
pub trait FromPrimitive: Sized {
    /// Converts from `isize`.
    fn from_isize(value: isize) -> Option<Self> {
        Self::from_i64(value as i64)
    }

    /// Converts from `i8`.
    fn from_i8(value: i8) -> Option<Self> {
        Self::from_i64(i64::from(value))
    }

    /// Converts from `i16`.
    fn from_i16(value: i16) -> Option<Self> {
        Self::from_i64(i64::from(value))
    }

    /// Converts from `i32`.
    fn from_i32(value: i32) -> Option<Self> {
        Self::from_i64(i64::from(value))
    }

    /// Converts from `i64`.
    fn from_i64(value: i64) -> Option<Self>;

    /// Converts from `i128`.
    fn from_i128(value: i128) -> Option<Self> {
        i64::try_from(value).ok().and_then(Self::from_i64)
    }

    /// Converts from `usize`.
    fn from_usize(value: usize) -> Option<Self> {
        u64::try_from(value).ok().and_then(Self::from_u64)
    }

    /// Converts from `u8`.
    fn from_u8(value: u8) -> Option<Self> {
        Self::from_u64(u64::from(value))
    }

    /// Converts from `u16`.
    fn from_u16(value: u16) -> Option<Self> {
        Self::from_u64(u64::from(value))
    }

    /// Converts from `u32`.
    fn from_u32(value: u32) -> Option<Self> {
        Self::from_u64(u64::from(value))
    }

    /// Converts from `u64`.
    fn from_u64(value: u64) -> Option<Self>;

    /// Converts from `u128`.
    fn from_u128(value: u128) -> Option<Self> {
        u64::try_from(value).ok().and_then(Self::from_u64)
    }

    /// Converts from `f32`, truncating its fractional part.
    fn from_f32(value: f32) -> Option<Self> {
        Self::from_f64(f64::from(value))
    }

    /// Converts from `f64`, truncating its fractional part.
    fn from_f64(value: f64) -> Option<Self> {
        if value >= i64::MIN as f64 && value < -(i64::MIN as f64) {
            Self::from_i64(value as i64)
        } else if value >= 0.0 && value < u64::MAX as f64 {
            Self::from_u64(value as u64)
        } else {
            None
        }
    }
}

/// Conversion to primitive numeric types.
pub trait ToPrimitive {
    /// Converts to `isize` when representable.
    fn to_isize(&self) -> Option<isize> {
        self.to_i64().and_then(|value| isize::try_from(value).ok())
    }

    /// Converts to `i8` when representable.
    fn to_i8(&self) -> Option<i8> {
        self.to_i64().and_then(|value| i8::try_from(value).ok())
    }

    /// Converts to `i16` when representable.
    fn to_i16(&self) -> Option<i16> {
        self.to_i64().and_then(|value| i16::try_from(value).ok())
    }

    /// Converts to `i32` when representable.
    fn to_i32(&self) -> Option<i32> {
        self.to_i64().and_then(|value| i32::try_from(value).ok())
    }

    /// Converts to `i64` when representable.
    fn to_i64(&self) -> Option<i64>;

    /// Converts to `i128` when representable.
    fn to_i128(&self) -> Option<i128> {
        self.to_i64().map(i128::from)
    }

    /// Converts to `usize` when representable.
    fn to_usize(&self) -> Option<usize> {
        self.to_u64().and_then(|value| usize::try_from(value).ok())
    }

    /// Converts to `u8` when representable.
    fn to_u8(&self) -> Option<u8> {
        self.to_u64().and_then(|value| u8::try_from(value).ok())
    }

    /// Converts to `u16` when representable.
    fn to_u16(&self) -> Option<u16> {
        self.to_u64().and_then(|value| u16::try_from(value).ok())
    }

    /// Converts to `u32` when representable.
    fn to_u32(&self) -> Option<u32> {
        self.to_u64().and_then(|value| u32::try_from(value).ok())
    }

    /// Converts to `u64` when representable.
    fn to_u64(&self) -> Option<u64>;

    /// Converts to `u128` when representable.
    fn to_u128(&self) -> Option<u128> {
        self.to_u64().map(u128::from)
    }

    /// Converts to `f32`.
    fn to_f32(&self) -> Option<f32> {
        self.to_f64().map(|value| value as f32)
    }

    /// Converts to `f64`.
    fn to_f64(&self) -> Option<f64> {
        self.to_i64()
            .map(|value| value as f64)
            .or_else(|| self.to_u64().map(|value| value as f64))
    }
}

// `Num` follows `num-traits` and requires owned forms of all five operators.
// The arithmetic itself remains in `big_int.rs`; these adapters only select
// the already implemented borrowed operations.
impl Sub for BigInt {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        &self - &rhs
    }
}

impl Mul for BigInt {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        &self * &rhs
    }
}

impl Div for BigInt {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        &self / &rhs
    }
}

impl Rem for BigInt {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        &self % &rhs
    }
}

impl Zero for BigInt {
    fn zero() -> Self {
        Self::from_u8(0)
    }

    fn is_zero(&self) -> bool {
        BigInt::is_zero(self)
    }
}

impl One for BigInt {
    fn one() -> Self {
        Self::from_u8(1)
    }

    fn is_one(&self) -> bool {
        self == &Self::from_u8(1)
    }
}

impl Num for BigInt {
    type FromStrRadixErr = ParseBigIntError;

    fn from_str_radix(value: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        BigInt::from_str_radix(value, radix)
    }
}

impl Signed for BigInt {
    fn abs(&self) -> Self {
        self.clone().abs()
    }

    fn abs_sub(&self, other: &Self) -> Self {
        if self <= other {
            Self::zero()
        } else {
            self - other
        }
    }

    fn signum(&self) -> Self {
        Self::from_i32(self.sign())
    }

    fn is_positive(&self) -> bool {
        self.sign() > 0
    }

    fn is_negative(&self) -> bool {
        self.sign() < 0
    }
}

impl CheckedAdd for BigInt {
    fn checked_add(&self, rhs: &Self) -> Option<Self> {
        Some(self + rhs)
    }
}

impl OverflowingAdd for BigInt {
    fn overflowing_add(&self, rhs: &Self) -> (Self, bool) {
        (self + rhs, false)
    }
}

impl WrappingAdd for BigInt {
    fn wrapping_add(&self, rhs: &Self) -> Self {
        self + rhs
    }
}

impl SaturatingAdd for BigInt {
    fn saturating_add(&self, rhs: &Self) -> Self {
        self + rhs
    }
}

impl FromPrimitive for BigInt {
    fn from_i64(value: i64) -> Option<Self> {
        Some(BigInt::from_i64(value))
    }

    fn from_i128(value: i128) -> Option<Self> {
        Some(BigInt::from_i128(value))
    }

    fn from_u64(value: u64) -> Option<Self> {
        Some(BigInt::from_u64(value))
    }

    fn from_u128(value: u128) -> Option<Self> {
        Some(BigInt::from_u128(value))
    }
}

impl ToPrimitive for BigInt {
    fn to_i64(&self) -> Option<i64> {
        i64::try_from(self).ok()
    }

    fn to_i128(&self) -> Option<i128> {
        i128::try_from(self).ok()
    }

    fn to_u64(&self) -> Option<u64> {
        u64::try_from(self).ok()
    }

    fn to_u128(&self) -> Option<u128> {
        u128::try_from(self).ok()
    }
}

impl Pow<u32> for BigInt {
    type Output = BigInt;

    fn pow(self, exponent: u32) -> Self::Output {
        BigInt::pow(&self, exponent)
    }
}

impl Pow<&u32> for BigInt {
    type Output = BigInt;

    fn pow(self, exponent: &u32) -> Self::Output {
        BigInt::pow(&self, *exponent)
    }
}

impl Pow<u32> for &BigInt {
    type Output = BigInt;

    fn pow(self, exponent: u32) -> Self::Output {
        BigInt::pow(self, exponent)
    }
}

impl Pow<&u32> for &BigInt {
    type Output = BigInt;

    fn pow(self, exponent: &u32) -> Self::Output {
        BigInt::pow(self, *exponent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add<L, R>(lhs: L, rhs: R) -> <L as Add<R>>::Output
    where
        L: Add<R>,
    {
        lhs + rhs
    }

    fn parse<T: Num>(value: &str, radix: u32) -> Result<T, T::FromStrRadixErr> {
        T::from_str_radix(value, radix)
    }

    #[test]
    fn numeric_identities_and_num_are_implemented() {
        let mut value = BigInt::from_i32(42);
        value.set_zero();
        assert!(Zero::is_zero(&value));

        value.set_one();
        assert!(value.is_one());
        assert_eq!(parse::<BigInt>("2a", 16).unwrap(), BigInt::from_i32(42));
    }

    #[test]
    fn signed_operations_are_implemented() {
        let negative = BigInt::from_i32(-42);
        let smaller = BigInt::from_i32(20);

        assert_eq!(Signed::abs(&negative), BigInt::from_i32(42));
        assert_eq!(negative.signum(), BigInt::from_i32(-1));
        assert!(negative.is_negative());
        assert_eq!(smaller.abs_sub(&BigInt::from_i32(50)), BigInt::zero());
    }

    #[test]
    fn arbitrary_precision_addition_never_reports_numeric_overflow() {
        let lhs = BigInt::from_u128(u128::MAX);
        let rhs = BigInt::from_u8(1);
        let expected = &lhs + &rhs;

        assert_eq!(lhs.checked_add(&rhs), Some(expected.clone()));
        assert_eq!(lhs.overflowing_add(&rhs), (expected.clone(), false));
        assert_eq!(lhs.wrapping_add(&rhs), expected.clone());
        assert_eq!(lhs.saturating_add(&rhs), expected);
    }

    #[test]
    fn primitive_conversions_are_implemented() {
        let value = <BigInt as FromPrimitive>::from_i128(i128::MIN).unwrap();

        assert_eq!(value.to_i128(), Some(i128::MIN));
        assert_eq!(value.to_u128(), None);
        assert_eq!(BigInt::from_u128(u128::MAX).to_u128(), Some(u128::MAX));
    }

    #[test]
    fn pow_supports_owned_and_borrowed_arguments() {
        let base = BigInt::from_i32(-2);
        let exponent = 3;

        assert_eq!(Pow::pow(base.clone(), exponent), BigInt::from_i32(-8));
        assert_eq!(Pow::pow(base.clone(), &exponent), BigInt::from_i32(-8));
        assert_eq!(Pow::pow(&base, exponent), BigInt::from_i32(-8));
        assert_eq!(Pow::pow(&base, &exponent), BigInt::from_i32(-8));
    }

    #[test]
    fn add_remains_exposed_for_generic_code() {
        let lhs = BigInt::from_i32(20);
        let rhs = BigInt::from_i32(22);

        assert_eq!(add(&lhs, &rhs), BigInt::from_i32(42));
    }
}
