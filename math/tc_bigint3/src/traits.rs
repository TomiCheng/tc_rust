//! Local numeric trait contracts.
//!
//! These interfaces are adapted from `num-traits` 0.2 and intentionally live
//! in this crate. No `num-traits` dependency is required, and these are distinct
//! Rust traits rather than drop-in implementations of `num_traits::*`.

use core::ops::{
    Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Sub, SubAssign,
};
#[cfg(feature = "rand_core")]
use rand_core::{Rng, TryRng};

#[cfg(feature = "rand_core")]
use crate::{NonZero, RandomBitsError};

/// A value with an additive identity.
pub trait Zero: Sized + Add<Self, Output = Self> {
    /// Returns zero.
    fn zero() -> Self;

    /// Replaces this value with zero.
    fn set_zero(&mut self) {
        *self = Self::zero();
    }

    /// Returns whether this value is zero.
    fn is_zero(&self) -> bool;
}

/// A value with a multiplicative identity.
pub trait One: Sized + Mul<Self, Output = Self> {
    /// Returns one.
    fn one() -> Self;

    /// Replaces this value with one.
    fn set_one(&mut self) {
        *self = Self::one();
    }

    /// Returns whether this value is one.
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

/// A [`Num`] whose basic operators accept a borrowed right-hand side.
pub trait NumRef: Num + for<'a> NumOps<&'a Self> {}

impl<T> NumRef for T where T: Num + for<'a> NumOps<&'a T> {}

/// A reference-like value whose operators accept owned and borrowed values.
pub trait RefNum<Base>: NumOps<Base, Base> + for<'a> NumOps<&'a Base, Base> {}

impl<T, Base> RefNum<Base> for T where T: NumOps<Base, Base> + for<'a> NumOps<&'a Base, Base> {}

/// The five basic assignment operators.
pub trait NumAssignOps<Rhs = Self>:
    AddAssign<Rhs> + SubAssign<Rhs> + MulAssign<Rhs> + DivAssign<Rhs> + RemAssign<Rhs>
{
}

impl<T, Rhs> NumAssignOps<Rhs> for T where
    T: AddAssign<Rhs> + SubAssign<Rhs> + MulAssign<Rhs> + DivAssign<Rhs> + RemAssign<Rhs>
{
}

/// A [`Num`] supporting all owned assignment operators.
pub trait NumAssign: Num + NumAssignOps {}

impl<T> NumAssign for T where T: Num + NumAssignOps {}

/// A [`NumAssign`] whose assignment operators accept borrowed values.
pub trait NumAssignRef: NumAssign + for<'a> NumAssignOps<&'a Self> {}

impl<T> NumAssignRef for T where T: NumAssign + for<'a> NumAssignOps<&'a T> {}

/// Base contract for numeric values.
pub trait Num: PartialEq + Zero + One + NumOps {
    /// Parsing error.
    type FromStrRadixErr;

    /// Parses a value in `radix`.
    fn from_str_radix(value: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr>;
}

/// Operations specific to signed values.
pub trait Signed: Sized + Num + Neg<Output = Self> {
    /// Returns the absolute value.
    fn abs(&self) -> Self;

    /// Returns `self - other` when positive, or zero otherwise.
    fn abs_sub(&self, other: &Self) -> Self;

    /// Returns negative one, zero, or positive one.
    fn signum(&self) -> Self;

    /// Returns whether the value is positive.
    fn is_positive(&self) -> bool;

    /// Returns whether the value is negative.
    fn is_negative(&self) -> bool;
}

/// Marker trait for numeric values which cannot be negative.
pub trait Unsigned: Num {}

/// Exponentiation with a caller-selected exponent type.
pub trait Pow<Rhs> {
    /// Result type.
    type Output;

    /// Raises `self` to `rhs`.
    fn pow(self, rhs: Rhs) -> Self::Output;
}

/// Squaring without requiring the caller to clone the operand.
pub trait Square {
    /// Squared value.
    type Output;

    /// Returns `self * self`.
    fn square(&self) -> Self::Output;
}

/// A combined quotient-and-remainder operation.
pub trait DivRem<Rhs = Self> {
    /// Quotient type.
    type Quotient;
    /// Remainder type.
    type Remainder;

    /// Returns the quotient and remainder together.
    fn div_rem(&self, rhs: &Rhs) -> (Self::Quotient, Self::Remainder);
}

/// Euclidean remainder, which is non-negative for signed values.
pub trait RemEuclid<Rhs = Self> {
    /// Remainder type.
    type Output;

    /// Returns the least non-negative remainder.
    fn rem_euclid(&self, rhs: &Rhs) -> Self::Output;
}

/// Greatest common divisor.
pub trait Gcd<Rhs = Self> {
    /// GCD result type.
    type Output;

    /// Returns the non-negative greatest common divisor.
    fn gcd(&self, rhs: &Rhs) -> Self::Output;
}

/// Modular multiplicative inverse.
pub trait ModInverse<Modulus = Self> {
    /// Inverse type.
    type Output;

    /// Returns `x` such that `self * x = 1 (mod modulus)`, when it exists.
    fn mod_inverse(&self, modulus: &Modulus) -> Option<Self::Output>;
}

/// Modular exponentiation.
pub trait ModPow<Exponent = Self, Modulus = Self> {
    /// Modular exponentiation result type.
    type Output;

    /// Returns `self^exponent mod modulus`.
    fn mod_pow(&self, exponent: &Exponent, modulus: &Modulus) -> Self::Output;
}

/// Random full-width value generation.
#[cfg(feature = "rand_core")]
pub trait Random: Sized {
    /// Generates a random value and preserves errors from the supplied RNG.
    fn try_random_from_rng<R: TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error>;

    /// Generates a random value from an infallible RNG.
    fn random_from_rng<R: Rng + ?Sized>(rng: &mut R) -> Self {
        match Self::try_random_from_rng(rng) {
            Ok(value) => value,
            Err(error) => match error {},
        }
    }
}

/// Random bits generation support.
#[cfg(feature = "rand_core")]
pub trait RandomBits: Sized {
    /// Generates a value in `0..2^bit_length`, preserving RNG errors.
    fn try_random_bits<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
    ) -> Result<Self, RandomBitsError<R::Error>>;

    /// Generates a value in `0..2^bit_length` with an explicit storage precision.
    fn try_random_bits_with_precision<R: TryRng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
        bits_precision: u32,
    ) -> Result<Self, RandomBitsError<R::Error>>;

    /// Generates a value in `0..2^bit_length` from an infallible RNG.
    fn random_bits<R: Rng + ?Sized>(rng: &mut R, bit_length: u32) -> Self {
        Self::try_random_bits(rng, bit_length)
            .unwrap_or_else(|error| panic!("random bit generation failed: {error}"))
    }

    /// Generates random bits using an explicit storage precision.
    fn random_bits_with_precision<R: Rng + ?Sized>(
        rng: &mut R,
        bit_length: u32,
        bits_precision: u32,
    ) -> Self {
        Self::try_random_bits_with_precision(rng, bit_length, bits_precision)
            .unwrap_or_else(|error| panic!("random bit generation failed: {error}"))
    }
}

/// Modular random number generation support.
#[cfg(feature = "rand_core")]
pub trait RandomMod: Sized + Zero {
    /// Generates a uniformly random value below `modulus` using rejection sampling.
    ///
    /// The operation is variable-time with respect to the public modulus.
    fn try_random_mod_vartime<R: TryRng + ?Sized>(
        rng: &mut R,
        modulus: &NonZero<Self>,
    ) -> Result<Self, R::Error>;

    /// Infallible wrapper around [`Self::try_random_mod_vartime`].
    fn random_mod_vartime<R: Rng + ?Sized>(rng: &mut R, modulus: &NonZero<Self>) -> Self {
        match Self::try_random_mod_vartime(rng, modulus) {
            Ok(value) => value,
            Err(error) => match error {},
        }
    }

    /// Deprecated alias for [`Self::try_random_mod_vartime`].
    #[deprecated(since = "0.1.0", note = "use try_random_mod_vartime")]
    fn try_random_mod<R: TryRng + ?Sized>(
        rng: &mut R,
        modulus: &NonZero<Self>,
    ) -> Result<Self, R::Error> {
        Self::try_random_mod_vartime(rng, modulus)
    }

    /// Deprecated alias for [`Self::random_mod_vartime`].
    #[deprecated(since = "0.1.0", note = "use random_mod_vartime")]
    fn random_mod<R: Rng + ?Sized>(rng: &mut R, modulus: &NonZero<Self>) -> Self {
        Self::random_mod_vartime(rng, modulus)
    }
}

/// Construction of a random probable prime with an exact bit length.
#[cfg(feature = "rand_core")]
pub trait ProbablePrime: Sized {
    /// Generates a probable prime using a default certainty of 100 bits.
    fn probable_prime<R: Rng + ?Sized>(rng: &mut R, bit_length: u32) -> Self;
}

/// Probabilistic primality testing.
#[cfg(feature = "rand_core")]
pub trait IsProbablePrime {
    /// Returns `false` for a proven composite and `true` for a probable prime.
    ///
    /// A certainty of zero skips testing and returns `true`.
    fn is_probable_prime<R: Rng + ?Sized>(&self, certainty: u32, rng: &mut R) -> bool;
}

/// Search for the smallest probable prime strictly greater than a value.
#[cfg(feature = "rand_core")]
pub trait NextProbablePrime {
    /// Result type. Fixed-width integers use `Option<Self>` to report overflow.
    type Output;

    /// Returns the next probable prime.
    fn next_probable_prime<R: Rng + ?Sized>(&self, rng: &mut R) -> Self::Output;
}

/// Common bit inspection and mutation operations.
pub trait BitOps {
    /// Result of the non-mutating bit operations.
    type Output;

    /// Returns the significant bit length.
    fn bit_length(&self) -> usize;

    /// Returns the number of bits which differ from sign extension.
    fn bit_count(&self) -> usize;

    /// Tests bit `index`.
    fn test_bit(&self, index: usize) -> bool;

    /// Returns a value with bit `index` set.
    fn set_bit(&self, index: usize) -> Self::Output;

    /// Returns a value with bit `index` cleared.
    fn clear_bit(&self, index: usize) -> Self::Output;

    /// Returns a value with bit `index` flipped.
    fn flip_bit(&self, index: usize) -> Self::Output;

    /// Returns the index of the least-significant set bit.
    fn lowest_set_bit(&self) -> Option<usize>;
}

/// Computes `self & !rhs`.
pub trait AndNot<Rhs = Self> {
    /// Result type.
    type Output;

    /// Clears every bit which is set in `rhs`.
    fn and_not(&self, rhs: &Rhs) -> Self::Output;
}

/// Checked addition.
pub trait CheckedAdd: Sized + Add<Self, Output = Self> {
    /// Returns the sum, or `None` if it is outside the numeric range.
    fn checked_add(&self, rhs: &Self) -> Option<Self>;
}

/// Checked subtraction.
pub trait CheckedSub: Sized + Sub<Self, Output = Self> {
    /// Returns the difference, or `None` if it is outside the numeric range.
    fn checked_sub(&self, rhs: &Self) -> Option<Self>;
}

/// Addition with an overflow flag.
pub trait OverflowingAdd: Sized + Add<Self, Output = Self> {
    /// Returns the wrapped sum and whether overflow occurred.
    fn overflowing_add(&self, rhs: &Self) -> (Self, bool);
}

/// Wrapping addition.
pub trait WrappingAdd: Sized + Add<Self, Output = Self> {
    /// Returns the sum modulo the type width.
    fn wrapping_add(&self, rhs: &Self) -> Self;
}

/// Saturating addition.
pub trait SaturatingAdd: Sized + Add<Self, Output = Self> {
    /// Returns the sum clamped to the numeric range.
    fn saturating_add(&self, rhs: &Self) -> Self;
}

/// Conversion from primitive numeric types.
pub trait FromPrimitive: Sized {
    /// Converts an `isize`.
    fn from_isize(value: isize) -> Option<Self> {
        Self::from_i64(value as i64)
    }

    /// Converts an `i8`.
    fn from_i8(value: i8) -> Option<Self> {
        Self::from_i64(i64::from(value))
    }

    /// Converts an `i16`.
    fn from_i16(value: i16) -> Option<Self> {
        Self::from_i64(i64::from(value))
    }

    /// Converts an `i32`.
    fn from_i32(value: i32) -> Option<Self> {
        Self::from_i64(i64::from(value))
    }

    /// Converts an `i64`.
    fn from_i64(value: i64) -> Option<Self>;

    /// Converts an `i128`.
    fn from_i128(value: i128) -> Option<Self> {
        i64::try_from(value).ok().and_then(Self::from_i64)
    }

    /// Converts a `usize`.
    fn from_usize(value: usize) -> Option<Self> {
        u64::try_from(value).ok().and_then(Self::from_u64)
    }

    /// Converts a `u8`.
    fn from_u8(value: u8) -> Option<Self> {
        Self::from_u64(u64::from(value))
    }

    /// Converts a `u16`.
    fn from_u16(value: u16) -> Option<Self> {
        Self::from_u64(u64::from(value))
    }

    /// Converts a `u32`.
    fn from_u32(value: u32) -> Option<Self> {
        Self::from_u64(u64::from(value))
    }

    /// Converts a `u64`.
    fn from_u64(value: u64) -> Option<Self>;

    /// Converts a `u128`.
    fn from_u128(value: u128) -> Option<Self> {
        u64::try_from(value).ok().and_then(Self::from_u64)
    }

    /// Converts an `f32`, truncating its fractional part.
    fn from_f32(value: f32) -> Option<Self> {
        Self::from_f64(f64::from(value))
    }

    /// Converts an `f64`, truncating its fractional part.
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

#[cfg(test)]
mod tests {
    use super::{
        AndNot, BitOps, CheckedAdd, CheckedSub, DivRem, FromPrimitive, Gcd, ModInverse, ModPow,
        Num, NumAssignRef, NumRef, One, OverflowingAdd, Pow, RefNum, RemEuclid, SaturatingAdd,
        Signed, Square, ToPrimitive, WrappingAdd, Zero,
    };
    use crate::{FixedBigInt, FixedBigUint};

    type I = FixedBigInt<2>;
    type U = FixedBigUint<2>;

    #[derive(Debug, Eq, PartialEq)]
    struct PrimitiveProbe(i64);

    impl FromPrimitive for PrimitiveProbe {
        fn from_i64(value: i64) -> Option<Self> {
            Some(Self(value))
        }

        fn from_u64(value: u64) -> Option<Self> {
            i64::try_from(value).ok().map(Self)
        }
    }

    fn assert_num_ref<T: NumRef>() {}
    fn assert_num_assign_ref<T: NumAssignRef>() {}
    fn assert_ref_num<T>()
    where
        for<'a> &'a T: RefNum<T>,
    {
    }

    #[test]
    fn identity_default_methods_and_numeric_marker_traits_work() {
        let mut value = U::from(9_u8);
        Zero::set_zero(&mut value);
        assert!(Zero::is_zero(&value));

        One::set_one(&mut value);
        assert!(One::is_one(&value));

        assert_num_ref::<U>();
        assert_num_assign_ref::<U>();
        assert_ref_num::<U>();
    }

    #[test]
    fn signed_trait_methods_cover_negative_zero_and_positive_values() {
        let negative = I::from(-7_i8);
        let zero = I::zero();
        let positive = I::from(3_i8);

        assert_eq!(Signed::abs(&negative), I::from(7_i8));
        assert_eq!(Signed::abs_sub(&positive, &negative), I::from(10_i8));
        assert_eq!(Signed::abs_sub(&negative, &positive), zero);
        assert_eq!(Signed::signum(&negative), I::from(-1_i8));
        assert_eq!(Signed::signum(&zero), zero);
        assert_eq!(Signed::signum(&positive), I::from(1_i8));
        assert!(Signed::is_negative(&negative));
        assert!(Signed::is_positive(&positive));
    }

    #[test]
    fn arithmetic_contracts_delegate_to_the_integer_implementations() {
        let seven = U::from(7_u8);
        let three = U::from(3_u8);
        let eleven = U::from(11_u8);

        assert_eq!(Pow::pow(seven, 2_u32), U::from(49_u8));
        assert_eq!(Pow::pow(&seven, &2_u32), U::from(49_u8));
        assert_eq!(Square::square(&seven), U::from(49_u8));
        assert_eq!(
            DivRem::div_rem(&seven, &three),
            (U::from(2_u8), U::from(1_u8))
        );
        assert_eq!(RemEuclid::rem_euclid(&seven, &three), U::from(1_u8));
        assert_eq!(Gcd::gcd(&U::from(21_u8), &U::from(6_u8)), U::from(3_u8));
        assert_eq!(
            ModInverse::mod_inverse(&three, &eleven),
            Some(U::from(4_u8))
        );
        assert_eq!(
            ModPow::mod_pow(&three, &U::from(4_u8), &eleven),
            U::from(4_u8)
        );
    }

    #[test]
    fn bit_and_addition_contracts_cover_each_method() {
        let value = U::from(0b1010_u8);
        assert_eq!(BitOps::bit_length(&value), 4);
        assert_eq!(BitOps::bit_count(&value), 2);
        assert!(BitOps::test_bit(&value, 3));
        assert_eq!(BitOps::set_bit(&value, 0), U::from(0b1011_u8));
        assert_eq!(BitOps::clear_bit(&value, 3), U::from(0b0010_u8));
        assert_eq!(BitOps::flip_bit(&value, 1), U::from(0b1000_u8));
        assert_eq!(BitOps::lowest_set_bit(&value), Some(1));
        assert_eq!(AndNot::and_not(&value, &U::from(0b0011_u8)), U::from(8_u8));

        let max = U::max_value();
        let one = U::from(1_u8);
        assert_eq!(CheckedAdd::checked_add(&max, &one), None);
        assert_eq!(CheckedSub::checked_sub(&U::zero(), &one), None);
        assert_eq!(
            OverflowingAdd::overflowing_add(&max, &one),
            (U::zero(), true)
        );
        assert_eq!(WrappingAdd::wrapping_add(&max, &one), U::zero());
        assert_eq!(SaturatingAdd::saturating_add(&max, &one), max);
    }

    #[test]
    fn from_primitive_default_methods_cover_all_source_types() {
        assert_eq!(U::from_isize(1), Some(U::from(1_u8)));
        assert_eq!(U::from_i8(2), Some(U::from(2_u8)));
        assert_eq!(U::from_i16(3), Some(U::from(3_u8)));
        assert_eq!(U::from_i32(4), Some(U::from(4_u8)));
        assert_eq!(U::from_i128(5), Some(U::from(5_u8)));
        assert_eq!(U::from_usize(6), Some(U::from(6_u8)));
        assert_eq!(U::from_u8(7), Some(U::from(7_u8)));
        assert_eq!(U::from_u16(8), Some(U::from(8_u8)));
        assert_eq!(U::from_u32(9), Some(U::from(9_u8)));
        assert_eq!(U::from_u128(10), Some(U::from(10_u8)));
        assert_eq!(U::from_f32(11.75), Some(U::from(11_u8)));
        assert_eq!(U::from_f64(12.75), Some(U::from(12_u8)));

        assert_eq!(U::from_i8(-1), None);
        assert_eq!(U::from_i128(i128::MAX), Some(U::from(i128::MAX as u128)));
        assert_eq!(U::from_f64(f64::NAN), None);
        assert_eq!(U::from_f64(f64::INFINITY), None);

        assert_eq!(PrimitiveProbe::from_i128(i128::MAX), None);
        assert_eq!(PrimitiveProbe::from_u128(u128::MAX), None);
    }

    #[test]
    fn to_primitive_default_methods_cover_all_destination_types() {
        let value = I::from(42_i8);
        assert_eq!(value.to_isize(), Some(42));
        assert_eq!(value.to_i8(), Some(42));
        assert_eq!(value.to_i16(), Some(42));
        assert_eq!(value.to_i32(), Some(42));
        assert_eq!(value.to_i128(), Some(42));
        assert_eq!(value.to_usize(), Some(42));
        assert_eq!(value.to_u8(), Some(42));
        assert_eq!(value.to_u16(), Some(42));
        assert_eq!(value.to_u32(), Some(42));
        assert_eq!(value.to_u128(), Some(42));
        assert_eq!(value.to_f32(), Some(42.0));
        assert_eq!(value.to_f64(), Some(42.0));

        let negative = I::from(-1_i8);
        assert_eq!(negative.to_usize(), None);
        assert_eq!(negative.to_u8(), None);

        let too_large = U::from(u64::MAX);
        assert_eq!(too_large.to_i8(), None);
        assert_eq!(too_large.to_i64(), None);
        assert_eq!(too_large.to_f64(), Some(u64::MAX as f64));
    }

    #[test]
    fn num_parsing_contract_calls_the_concrete_parser() {
        assert_eq!(
            <U as Num>::from_str_radix("ff", 16).expect("valid hexadecimal"),
            U::from(255_u16)
        );
    }
}
