//! Arbitrary-precision signed integers.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::ops::{Neg, Shl, ShlAssign, Shr, ShrAssign};

#[cfg(test)]
use crate::ConversionError;
use crate::arithmetic;
use crate::encoding;
use crate::traits::{
    BitOps, CheckedNeg, CheckedShl, CheckedShr, Gcd, ModInverse, ModPow, Num, One, Pow, Signed,
    WrappingNeg, Zero,
};
use crate::{BigUint, Limb, ParseBigIntError, Word};

mod add;
mod array;
mod bit_and;
mod bit_not;
mod bit_or;
mod bit_xor;
mod cmp;
mod div;
mod from;
mod mul;
mod sub;

/// A signed integer whose precision grows as needed.
///
/// Limbs are stored in canonical little-endian two's-complement form. Zero has
/// no limbs; other values have no redundant high sign-extension limbs.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct BigInt {
    limbs: Vec<Limb>,
}

impl BigInt {
    pub(crate) fn from_limbs(mut limbs: Vec<Limb>) -> Self {
        encoding::normalize_signed(&mut limbs);
        Self { limbs }
    }

    pub(crate) fn from_sign_magnitude(negative: bool, mut magnitude: Vec<Limb>) -> Self {
        arithmetic::normalize(&mut magnitude);
        if magnitude.is_empty() {
            return Self::default();
        }

        if !negative {
            if magnitude.last().expect("non-empty").0 >> (Word::BITS - 1) != 0 {
                magnitude.push(Limb(0));
            }
            return Self::from_limbs(magnitude);
        }

        for word in &mut magnitude {
            word.0 = !word.0;
        }
        arithmetic::add_small(&mut magnitude, 1);
        if magnitude.last().expect("non-empty").0 >> (Word::BITS - 1) == 0 {
            magnitude.push(Limb(Word::MAX));
        }
        Self::from_limbs(magnitude)
    }

    fn sign_magnitude(&self) -> (bool, Vec<Limb>) {
        if !self.is_negative() {
            let mut magnitude = self.limbs.clone();
            arithmetic::normalize(&mut magnitude);
            return (false, magnitude);
        }

        let mut magnitude: Vec<Limb> = self.limbs.iter().map(|word| Limb(!word.0)).collect();
        arithmetic::add_small(&mut magnitude, 1);
        arithmetic::normalize(&mut magnitude);
        (true, magnitude)
    }

    /// Borrows the canonical little-endian two's-complement limbs.
    pub fn as_limbs(&self) -> &[Limb] {
        &self.limbs
    }

    /// Returns whether the value is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    /// Returns whether the value is negative.
    pub fn is_negative(&self) -> bool {
        encoding::is_negative(&self.limbs)
    }

    /// Returns the absolute value.
    pub fn abs(&self) -> Self {
        let (_, magnitude) = self.sign_magnitude();
        Self::from_sign_magnitude(false, magnitude)
    }

    /// Returns the non-negative greatest common divisor.
    pub fn gcd(&self, other: &Self) -> Self {
        let mut left = self.abs();
        let mut right = other.abs();
        while !right.is_zero() {
            let remainder = &left % &right;
            left = right;
            right = remainder;
        }
        left
    }

    /// Returns the modular multiplicative inverse, when it exists.
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        assert!(modulus.is_positive(), "modulus must be positive");
        let mut old_remainder = modulus.clone();
        let mut remainder = self.rem_euclid(modulus);
        let mut old_coefficient = Self::zero();
        let mut coefficient = Self::one();

        while !remainder.is_zero() {
            let quotient = &old_remainder / &remainder;
            let next_remainder = &old_remainder - &quotient * &remainder;
            let next_coefficient = &old_coefficient - &quotient * &coefficient;
            old_remainder = remainder;
            remainder = next_remainder;
            old_coefficient = coefficient;
            coefficient = next_coefficient;
        }

        (old_remainder == Self::one()).then(|| old_coefficient.rem_euclid(modulus))
    }

    /// Returns `self^exponent mod modulus`.
    ///
    /// A negative exponent uses the modular inverse of the positive-power
    /// result. The modulus must be positive.
    pub fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        assert!(modulus.is_positive(), "modulus must be positive");
        let (negative_exponent, exponent_magnitude) = exponent.sign_magnitude();
        let exponent = BigUint::from_limbs(exponent_magnitude);
        let base = self.rem_euclid(modulus);
        let base = BigUint::from_limbs(base.as_limbs().to_vec());
        let unsigned_modulus = BigUint::from_limbs(modulus.as_limbs().to_vec());
        let result = base.mod_pow(&exponent, &unsigned_modulus);
        let result = Self::from_sign_magnitude(false, result.as_limbs().to_vec());

        if negative_exponent {
            result
                .mod_inverse(modulus)
                .expect("base is not invertible for a negative exponent")
        } else {
            result
        }
    }

    /// Returns the significant bit length excluding sign extension.
    pub fn bit_length(&self) -> usize {
        if self.is_negative() {
            (!self).bit_length()
        } else {
            arithmetic::bit_len(&self.limbs)
        }
    }

    /// Counts bits which differ from the infinite sign extension.
    pub fn bit_count(&self) -> usize {
        if self.is_negative() {
            self.limbs
                .iter()
                .map(|word| (!word.0).count_ones() as usize)
                .sum()
        } else {
            self.limbs
                .iter()
                .map(|word| word.0.count_ones() as usize)
                .sum()
        }
    }

    /// Tests a bit using infinite two's-complement sign extension.
    pub fn test_bit(&self, index: usize) -> bool {
        let word = index / Word::BITS as usize;
        let bit = index % Word::BITS as usize;
        self.limbs
            .get(word)
            .map_or(self.is_negative(), |word| word.0 >> bit & 1 != 0)
    }

    /// Returns a value with `index` set.
    pub fn set_bit(&self, index: usize) -> Self {
        self | &(Self::one() << index)
    }

    /// Returns a value with `index` cleared.
    pub fn clear_bit(&self, index: usize) -> Self {
        self & &!(Self::one() << index)
    }

    /// Returns a value with `index` flipped.
    pub fn flip_bit(&self, index: usize) -> Self {
        self ^ &(Self::one() << index)
    }

    /// Returns the index of the least-significant set bit.
    pub fn lowest_set_bit(&self) -> Option<usize> {
        self.limbs
            .iter()
            .enumerate()
            .find(|(_, word)| word.0 != 0)
            .map(|(index, word)| index * Word::BITS as usize + word.0.trailing_zeros() as usize)
    }

    /// Parses a signed value in radix `2..=36`.
    pub fn from_str_radix(value: &str, radix: u32) -> Result<Self, ParseBigIntError> {
        let (negative, magnitude) = arithmetic::parse_unsigned(value, radix)?;
        Ok(Self::from_sign_magnitude(negative, magnitude))
    }

    /// Formats the value in radix `2..=36`.
    pub fn to_str_radix(&self, radix: u32) -> String {
        let (negative, magnitude) = self.sign_magnitude();
        let mut output = BigUint::from_limbs(magnitude).to_str_radix(radix);
        if negative {
            output.insert(0, '-');
        }
        output
    }

    fn fmt_radix(
        &self,
        radix: u32,
        uppercase: bool,
        prefix: &'static str,
        output: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let (negative, magnitude) = self.sign_magnitude();
        let mut digits = BigUint::from_limbs(magnitude).to_str_radix(radix);
        if uppercase {
            digits.make_ascii_uppercase();
        }
        output.pad_integral(
            !negative,
            if output.alternate() { prefix } else { "" },
            &digits,
        )
    }

    fn neg_ref(value: &Self) -> Self {
        let (negative, magnitude) = value.sign_magnitude();
        Self::from_sign_magnitude(!negative, magnitude)
    }
}

impl Neg for &BigInt {
    type Output = BigInt;

    fn neg(self) -> Self::Output {
        BigInt::neg_ref(self)
    }
}

impl Neg for BigInt {
    type Output = BigInt;

    fn neg(self) -> Self::Output {
        -&self
    }
}

impl CheckedNeg for BigInt {
    fn checked_neg(&self) -> Option<Self> {
        Some(-self)
    }
}

impl WrappingNeg for BigInt {
    fn wrapping_neg(&self) -> Self {
        -self
    }
}

impl Shl<usize> for &BigInt {
    type Output = BigInt;

    fn shl(self, rhs: usize) -> Self::Output {
        let (negative, magnitude) = self.sign_magnitude();
        BigInt::from_sign_magnitude(negative, arithmetic::shl(&magnitude, rhs))
    }
}

impl Shl<usize> for BigInt {
    type Output = BigInt;

    fn shl(self, rhs: usize) -> Self::Output {
        &self << rhs
    }
}

impl Shr<usize> for &BigInt {
    type Output = BigInt;

    fn shr(self, rhs: usize) -> Self::Output {
        let (negative, magnitude) = self.sign_magnitude();
        let discarded = negative && arithmetic::truncated_bits_are_nonzero(&magnitude, rhs);
        let mut shifted = arithmetic::shr(&magnitude, rhs);
        if discarded {
            arithmetic::add_small(&mut shifted, 1);
        }
        BigInt::from_sign_magnitude(negative, shifted)
    }
}

impl Shr<usize> for BigInt {
    type Output = BigInt;

    fn shr(self, rhs: usize) -> Self::Output {
        &self >> rhs
    }
}

impl CheckedShl for BigInt {
    fn checked_shl(&self, rhs: u32) -> Option<Self> {
        Some(self << rhs as usize)
    }
}

impl CheckedShr for BigInt {
    fn checked_shr(&self, rhs: u32) -> Option<Self> {
        Some(self >> rhs as usize)
    }
}

impl ShlAssign<usize> for BigInt {
    fn shl_assign(&mut self, rhs: usize) {
        *self = &*self << rhs;
    }
}

impl ShrAssign<usize> for BigInt {
    fn shr_assign(&mut self, rhs: usize) {
        *self = &*self >> rhs;
    }
}

impl fmt::Display for BigInt {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_radix(10, false, "", output)
    }
}

impl fmt::Debug for BigInt {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, output)
    }
}

macro_rules! impl_big_int_format {
    ($trait:ident, $radix:expr, $uppercase:expr, $prefix:expr) => {
        impl fmt::$trait for BigInt {
            fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.fmt_radix($radix, $uppercase, $prefix, output)
            }
        }
    };
}

impl_big_int_format!(Binary, 2, false, "0b");
impl_big_int_format!(Octal, 8, false, "0o");
impl_big_int_format!(LowerHex, 16, false, "0x");
impl_big_int_format!(UpperHex, 16, true, "0x");

impl Zero for BigInt {
    fn zero() -> Self {
        Self::default()
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}

impl One for BigInt {
    fn one() -> Self {
        Self::from(1_u8)
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
        self.abs()
    }

    fn abs_sub(&self, other: &Self) -> Self {
        if self <= other {
            Self::zero()
        } else {
            self - other
        }
    }

    fn signum(&self) -> Self {
        match self.cmp(&Self::zero()) {
            Ordering::Less => Self::from(-1_i8),
            Ordering::Equal => Self::zero(),
            Ordering::Greater => Self::one(),
        }
    }

    fn is_positive(&self) -> bool {
        !self.is_zero() && !self.is_negative()
    }

    fn is_negative(&self) -> bool {
        self.is_negative()
    }
}

impl Pow<u32> for BigInt {
    type Output = Self;

    fn pow(self, mut exponent: u32) -> Self::Output {
        let mut base = self;
        let mut result = Self::one();
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

impl Pow<&u32> for BigInt {
    type Output = Self;

    fn pow(self, exponent: &u32) -> Self::Output {
        Pow::pow(self, *exponent)
    }
}

impl Pow<u32> for &BigInt {
    type Output = BigInt;

    fn pow(self, exponent: u32) -> Self::Output {
        Pow::pow(self.clone(), exponent)
    }
}

impl Pow<&u32> for &BigInt {
    type Output = BigInt;

    fn pow(self, exponent: &u32) -> Self::Output {
        Pow::pow(self.clone(), *exponent)
    }
}

impl Gcd for BigInt {
    type Output = Self;

    fn gcd(&self, rhs: &Self) -> Self::Output {
        BigInt::gcd(self, rhs)
    }
}

impl ModInverse for BigInt {
    type Output = Self;

    fn mod_inverse(&self, modulus: &Self) -> Option<Self::Output> {
        BigInt::mod_inverse(self, modulus)
    }
}

impl ModPow for BigInt {
    type Output = Self;

    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self::Output {
        BigInt::mod_pow(self, exponent, modulus)
    }
}

impl BitOps for BigInt {
    type Output = Self;

    fn bit_length(&self) -> usize {
        BigInt::bit_length(self)
    }

    fn bit_count(&self) -> usize {
        BigInt::bit_count(self)
    }

    fn test_bit(&self, index: usize) -> bool {
        BigInt::test_bit(self, index)
    }

    fn set_bit(&self, index: usize) -> Self::Output {
        BigInt::set_bit(self, index)
    }

    fn clear_bit(&self, index: usize) -> Self::Output {
        BigInt::clear_bit(self, index)
    }

    fn flip_bit(&self, index: usize) -> Self::Output {
        BigInt::flip_bit(self, index)
    }

    fn lowest_set_bit(&self) -> Option<usize> {
        BigInt::lowest_set_bit(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FixedBigInt;
    use crate::traits::{FromPrimitive, ToPrimitive};
    use alloc::string::ToString;

    #[test]
    fn signed_external_units_round_trip() {
        for value in [i128::MIN, -129, -128, -1, 0, 1, 127, 128, i128::MAX] {
            let value = BigInt::from(value);
            assert_eq!(BigInt::from_le_bytes(&value.to_le_bytes()), value);
            assert_eq!(BigInt::from_le_u32(&value.to_le_u32()), value);
            assert_eq!(BigInt::from_le_u64(&value.to_le_u64()), value);
        }
    }

    #[test]
    fn right_shift_is_arithmetic() {
        assert_eq!((BigInt::from(-3_i8) >> 1).to_i64(), Some(-2));
        assert_eq!((BigInt::from(3_i8) >> 1).to_i64(), Some(1));
    }

    #[test]
    fn bitwise_operations_use_infinite_sign_extension() {
        let minus_one = BigInt::from(-1_i8);
        let value = BigInt::from(0x1234_u16);

        assert_eq!((&minus_one & &value), value);
        assert_eq!((&minus_one | &value), minus_one);
        assert_eq!((&minus_one ^ &value).to_i64(), Some(!0x1234_i64));
    }

    #[test]
    fn number_theory_operations_match_known_values() {
        let three = BigInt::from(3_i8);
        let seven = BigInt::from(7_i8);

        assert_eq!(
            BigInt::from(-12_i8).gcd(&BigInt::from(18_i8)),
            BigInt::from(6_i8)
        );
        assert_eq!(BigInt::from(-7_i8).rem_euclid(&three), BigInt::from(2_i8));
        assert_eq!(three.mod_inverse(&seven), Some(BigInt::from(5_i8)));
        assert_eq!(
            three.mod_pow(&BigInt::from(4_i8), &seven),
            BigInt::from(4_i8)
        );
        assert_eq!(
            three.mod_pow(&BigInt::from(-1_i8), &seven),
            BigInt::from(5_i8)
        );
    }

    #[test]
    fn signed_bit_inspection_matches_twos_complement() {
        let value = BigInt::from(-8_i8);

        assert_eq!(value.bit_length(), 3);
        assert_eq!(value.bit_count(), 3);
        assert_eq!(value.lowest_set_bit(), Some(3));
        assert!(value.test_bit(100));
        assert_eq!(value.clear_bit(3), BigInt::from(-16_i8));
    }

    #[test]
    fn conversion_writers_and_fixed_width_bridge_cover_signed_and_unsigned_inputs() {
        let negative = BigInt::from_le_bytes(&[0xfe]);
        assert_eq!(negative, BigInt::from(-2_i8));
        assert_eq!(BigInt::from(&[0xfe_u8][..]), negative);
        assert_eq!(BigInt::from(&[u32::MAX - 1][..]), negative);
        assert_eq!(BigInt::from(&[u64::MAX - 1][..]), negative);
        assert_eq!(
            BigInt::from_unsigned_le_bytes(&[0xfe]),
            BigInt::from(254_u8)
        );
        assert_eq!(
            BigInt::from_unsigned_le_u32(&[u32::MAX]),
            BigInt::from(u32::MAX)
        );
        assert_eq!(
            BigInt::from_unsigned_le_u64(&[u64::MAX]),
            BigInt::from(u64::MAX)
        );

        let mut bytes = [0_u8; 1];
        let mut words32 = [0_u32; 1];
        let mut words64 = [0_u64; 1];
        assert_eq!(negative.write_le_bytes(&mut bytes), Ok(1));
        assert_eq!(negative.write_le_u32(&mut words32), Ok(1));
        assert_eq!(negative.write_le_u64(&mut words64), Ok(1));
        assert_eq!(bytes, [0xfe]);
        assert_eq!(
            negative.write_le_bytes(&mut []),
            Err(ConversionError::BufferTooSmall)
        );
        assert_eq!(
            negative.write_le_u32(&mut []),
            Err(ConversionError::BufferTooSmall)
        );
        assert_eq!(
            negative.write_le_u64(&mut []),
            Err(ConversionError::BufferTooSmall)
        );

        type I = FixedBigInt<2>;
        let fixed = I::try_from(&negative).expect("minus two fits");
        assert_eq!(BigInt::from(fixed), negative);
        assert_eq!(
            FixedBigInt::<0>::try_from(&BigInt::zero()),
            Ok(FixedBigInt::zero())
        );
        assert_eq!(
            FixedBigInt::<0>::try_from(&negative),
            Err(ConversionError::InputTooLarge)
        );
        assert_eq!(
            FixedBigInt::<1>::try_from(&(BigInt::one() << Word::BITS as usize)),
            Err(ConversionError::InputTooLarge)
        );
    }

    #[test]
    fn negation_bitwise_and_shift_operators_cover_all_ownership_forms() {
        let left = BigInt::from(0b1100_i8);
        let right = BigInt::from(0b1010_i8);

        macro_rules! assert_forms {
            ($operator:tt, $expected:expr) => {{
                assert_eq!(&left $operator &right, BigInt::from($expected));
                assert_eq!(&left $operator right.clone(), BigInt::from($expected));
                assert_eq!(left.clone() $operator &right, BigInt::from($expected));
                assert_eq!(left.clone() $operator right.clone(), BigInt::from($expected));
            }};
        }

        assert_forms!(&, 0b1000_i8);
        assert_forms!(|, 0b1110_i8);
        assert_forms!(^, 0b0110_i8);
        assert_eq!(-&left, BigInt::from(-12_i8));
        assert_eq!(-left.clone(), BigInt::from(-12_i8));
        assert_eq!(!&left, BigInt::from(!12_i8));
        assert_eq!(!left.clone(), BigInt::from(!12_i8));
        assert_eq!(&left << 2, BigInt::from(48_i8));
        assert_eq!(left.clone() << 2, BigInt::from(48_i8));
        assert_eq!(&left >> 2, BigInt::from(3_i8));
        assert_eq!(left >> 2, BigInt::from(3_i8));

        let mut assigned = BigInt::from(-1_i8);
        assigned &= &BigInt::from(0b1110_i8);
        assigned |= BigInt::from(1_i8);
        assigned ^= &BigInt::from(0b0101_i8);
        assigned <<= 2;
        assigned >>= 1;
        assert_eq!(assigned, BigInt::from(20_i8));
    }

    #[test]
    fn parsing_formatting_comparison_and_remaining_bit_operations_are_covered() {
        assert_eq!(BigInt::from_str_radix("+7f", 16), Ok(BigInt::from(127_i8)));
        assert_eq!(BigInt::from_str_radix("-7f", 16), Ok(BigInt::from(-127_i8)));
        assert_eq!(
            BigInt::from_str_radix("", 10),
            Err(ParseBigIntError::InvalidDigit)
        );
        assert_eq!(BigInt::from(-42_i8).to_str_radix(10), "-42");
        assert_eq!(BigInt::from(-42_i8).to_string(), "-42");
        assert!(BigInt::zero().is_zero());
        assert!(!BigInt::zero().is_negative());
        assert_eq!(BigInt::from(-7_i8).abs(), BigInt::from(7_i8));

        let value = BigInt::from(0b1010_i8);
        assert_eq!(value.set_bit(0), BigInt::from(0b1011_i8));
        assert_eq!(value.flip_bit(1), BigInt::from(0b1000_i8));
        assert_eq!(
            value.and_not(&BigInt::from(0b0011_i8)),
            BigInt::from(0b1000_i8)
        );
        assert_eq!(BigInt::zero().lowest_set_bit(), None);
        assert!(!BigInt::zero().test_bit(100));
    }

    #[test]
    fn conversion_traits_cover_dynamic_signed_specific_paths() {
        let value = BigInt::from(-5_i8);
        assert_eq!(Pow::pow(value.clone(), &2_u32), BigInt::from(25_i8));
        assert_eq!(Pow::pow(&value, 2_u32), BigInt::from(25_i8));
        assert_eq!(Pow::pow(&value, &2_u32), BigInt::from(25_i8));

        assert_eq!(BigInt::from_i64(-9), Some(BigInt::from(-9_i8)));
        assert_eq!(BigInt::from_i128(i128::MIN), Some(BigInt::from(i128::MIN)));
        assert_eq!(BigInt::from_u64(u64::MAX), Some(BigInt::from(u64::MAX)));
        assert_eq!(BigInt::from_u128(u128::MAX), Some(BigInt::from(u128::MAX)));
        assert_eq!(BigInt::from(i128::MIN).to_i128(), Some(i128::MIN));
        assert_eq!(BigInt::from(-1_i8).to_u128(), None);
        assert_eq!(BigInt::from(u128::MAX).to_i128(), None);
        assert_eq!(BigInt::from(u64::MAX).to_u64(), Some(u64::MAX));
    }

    #[test]
    #[should_panic(expected = "modulus must be positive")]
    fn modular_inverse_rejects_non_positive_modulus() {
        let _ = BigInt::from(1_i8).mod_inverse(&BigInt::zero());
    }

    #[test]
    #[should_panic(expected = "modulus must be positive")]
    fn modular_power_rejects_non_positive_modulus() {
        let _ = BigInt::from(1_i8).mod_pow(&BigInt::from(2_i8), &BigInt::from(-3_i8));
    }

    #[test]
    #[should_panic(expected = "base is not invertible for a negative exponent")]
    fn negative_modular_power_rejects_a_non_invertible_base() {
        let _ = BigInt::from(2_i8).mod_pow(&BigInt::from(-1_i8), &BigInt::from(4_i8));
    }
}
