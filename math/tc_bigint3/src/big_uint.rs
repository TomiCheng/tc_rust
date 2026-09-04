//! Arbitrary-precision unsigned integers.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::ops::{Shl, ShlAssign, Shr, ShrAssign};

#[cfg(test)]
use crate::ConversionError;
use crate::arithmetic;
use crate::traits::{
    BitOps, CheckedShl, CheckedShr, Gcd, ModInverse, ModPow, Num, One, Pow, Unsigned, Zero,
};
use crate::{BigInt, Limb, ParseBigIntError, Word};

mod add;
mod array;
mod bit_and;
mod bit_or;
mod bit_xor;
mod cmp;
mod div;
mod from;
mod mul;
mod sub;

/// An unsigned integer whose precision grows as needed.
///
/// Limbs are stored from least significant to most significant. Zero has an
/// empty limb vector; non-zero values never contain redundant high zero limbs.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct BigUint {
    limbs: Vec<Limb>,
}

impl BigUint {
    pub(crate) fn from_limbs(mut limbs: Vec<Limb>) -> Self {
        arithmetic::normalize(&mut limbs);
        Self { limbs }
    }

    /// Borrows the canonical little-endian limbs.
    pub fn as_limbs(&self) -> &[Limb] {
        &self.limbs
    }

    /// Returns the number of significant bits.
    pub fn bits(&self) -> usize {
        arithmetic::bit_len(&self.limbs)
    }

    /// Returns whether the value is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    /// Returns the greatest common divisor.
    pub fn gcd(&self, other: &Self) -> Self {
        let mut left = self.clone();
        let mut right = other.clone();
        while !right.is_zero() {
            let remainder = &left % &right;
            left = right;
            right = remainder;
        }
        left
    }

    /// Returns the modular multiplicative inverse, when it exists.
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        let value = BigInt::from_unsigned_le_u64(&self.to_le_u64());
        let modulus = BigInt::from_unsigned_le_u64(&modulus.to_le_u64());
        value
            .mod_inverse(&modulus)
            .map(|inverse| Self::from_le_u64(&inverse.to_le_u64()))
    }

    /// Returns `self^exponent mod modulus`.
    pub fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        Self::from_limbs(arithmetic::mod_pow(
            &self.limbs,
            &exponent.limbs,
            &modulus.limbs,
        ))
    }

    /// Returns whether bit `index` is set.
    pub fn test_bit(&self, index: usize) -> bool {
        self.limbs
            .get(index / Word::BITS as usize)
            .is_some_and(|word| word.0 >> (index % Word::BITS as usize) & 1 != 0)
    }

    /// Counts all set bits.
    pub fn bit_count(&self) -> usize {
        self.limbs
            .iter()
            .map(|word| word.0.count_ones() as usize)
            .sum()
    }

    /// Returns a value with bit `index` set.
    pub fn set_bit(&self, index: usize) -> Self {
        let mut limbs = self.limbs.clone();
        let word_index = index / Word::BITS as usize;
        let needed = word_index + 1;
        if limbs.len() < needed {
            limbs.resize(needed, Limb(0));
        }
        limbs[word_index].0 |= (1 as Word) << (index % Word::BITS as usize);
        Self::from_limbs(limbs)
    }

    /// Returns a value with bit `index` cleared.
    pub fn clear_bit(&self, index: usize) -> Self {
        let mut limbs = self.limbs.clone();
        if let Some(word) = limbs.get_mut(index / Word::BITS as usize) {
            word.0 &= !((1 as Word) << (index % Word::BITS as usize));
        }
        Self::from_limbs(limbs)
    }

    /// Returns a value with bit `index` flipped.
    pub fn flip_bit(&self, index: usize) -> Self {
        let mut limbs = self.limbs.clone();
        let word_index = index / Word::BITS as usize;
        let needed = word_index + 1;
        if limbs.len() < needed {
            limbs.resize(needed, Limb(0));
        }
        limbs[word_index].0 ^= (1 as Word) << (index % Word::BITS as usize);
        Self::from_limbs(limbs)
    }

    /// Returns the index of the least-significant set bit.
    pub fn lowest_set_bit(&self) -> Option<usize> {
        self.limbs
            .iter()
            .enumerate()
            .find(|(_, word)| word.0 != 0)
            .map(|(index, word)| index * Word::BITS as usize + word.0.trailing_zeros() as usize)
    }

    /// Parses an unsigned value in radix `2..=36`.
    pub fn from_str_radix(value: &str, radix: u32) -> Result<Self, ParseBigIntError> {
        let (negative, limbs) = arithmetic::parse_unsigned(value, radix)?;
        if negative {
            return Err(ParseBigIntError::NegativeUnsigned);
        }
        Ok(Self::from_limbs(limbs))
    }

    /// Formats the value in radix `2..=36`.
    pub fn to_str_radix(&self, radix: u32) -> String {
        assert!((2..=36).contains(&radix), "radix must be in 2..=36");
        if self.is_zero() {
            return String::from("0");
        }

        let mut words = self.limbs.clone();
        let mut digits = Vec::new();
        while !words.is_empty() {
            let digit = arithmetic::div_rem_small(&mut words, radix as Word) as u8;
            digits.push(if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            });
        }
        digits.reverse();
        String::from_utf8(digits).expect("radix digits are ASCII")
    }

    fn fmt_radix(
        &self,
        radix: u32,
        uppercase: bool,
        prefix: &'static str,
        output: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let mut digits = self.to_str_radix(radix);
        if uppercase {
            digits.make_ascii_uppercase();
        }
        output.pad_integral(true, if output.alternate() { prefix } else { "" }, &digits)
    }
}

impl Shl<usize> for &BigUint {
    type Output = BigUint;

    fn shl(self, rhs: usize) -> Self::Output {
        BigUint::from_limbs(arithmetic::shl(&self.limbs, rhs))
    }
}

impl Shl<usize> for BigUint {
    type Output = BigUint;

    fn shl(self, rhs: usize) -> Self::Output {
        &self << rhs
    }
}

impl Shr<usize> for &BigUint {
    type Output = BigUint;

    fn shr(self, rhs: usize) -> Self::Output {
        BigUint::from_limbs(arithmetic::shr(&self.limbs, rhs))
    }
}

impl Shr<usize> for BigUint {
    type Output = BigUint;

    fn shr(self, rhs: usize) -> Self::Output {
        &self >> rhs
    }
}

impl CheckedShl for BigUint {
    fn checked_shl(&self, rhs: u32) -> Option<Self> {
        Some(self << rhs as usize)
    }
}

impl CheckedShr for BigUint {
    fn checked_shr(&self, rhs: u32) -> Option<Self> {
        Some(self >> rhs as usize)
    }
}

impl ShlAssign<usize> for BigUint {
    fn shl_assign(&mut self, rhs: usize) {
        *self = &*self << rhs;
    }
}

impl ShrAssign<usize> for BigUint {
    fn shr_assign(&mut self, rhs: usize) {
        *self = &*self >> rhs;
    }
}

impl fmt::Display for BigUint {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_radix(10, false, "", output)
    }
}

impl fmt::Debug for BigUint {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, output)
    }
}

macro_rules! impl_big_uint_format {
    ($trait:ident, $radix:expr, $uppercase:expr, $prefix:expr) => {
        impl fmt::$trait for BigUint {
            fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.fmt_radix($radix, $uppercase, $prefix, output)
            }
        }
    };
}

impl_big_uint_format!(Binary, 2, false, "0b");
impl_big_uint_format!(Octal, 8, false, "0o");
impl_big_uint_format!(LowerHex, 16, false, "0x");
impl_big_uint_format!(UpperHex, 16, true, "0x");

impl Zero for BigUint {
    fn zero() -> Self {
        Self::default()
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}

impl One for BigUint {
    fn one() -> Self {
        Self::from(1_u8)
    }
}

impl Num for BigUint {
    type FromStrRadixErr = ParseBigIntError;

    fn from_str_radix(value: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        BigUint::from_str_radix(value, radix)
    }
}

impl Unsigned for BigUint {}

impl Pow<u32> for BigUint {
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

impl Pow<&u32> for BigUint {
    type Output = Self;

    fn pow(self, exponent: &u32) -> Self::Output {
        Pow::pow(self, *exponent)
    }
}

impl Pow<u32> for &BigUint {
    type Output = BigUint;

    fn pow(self, exponent: u32) -> Self::Output {
        Pow::pow(self.clone(), exponent)
    }
}

impl Pow<&u32> for &BigUint {
    type Output = BigUint;

    fn pow(self, exponent: &u32) -> Self::Output {
        Pow::pow(self.clone(), *exponent)
    }
}

impl Gcd for BigUint {
    type Output = Self;

    fn gcd(&self, rhs: &Self) -> Self::Output {
        BigUint::gcd(self, rhs)
    }
}

impl ModInverse for BigUint {
    type Output = Self;

    fn mod_inverse(&self, modulus: &Self) -> Option<Self::Output> {
        BigUint::mod_inverse(self, modulus)
    }
}

impl ModPow for BigUint {
    type Output = Self;

    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self::Output {
        BigUint::mod_pow(self, exponent, modulus)
    }
}

impl BitOps for BigUint {
    type Output = Self;

    fn bit_length(&self) -> usize {
        self.bits()
    }

    fn bit_count(&self) -> usize {
        BigUint::bit_count(self)
    }

    fn test_bit(&self, index: usize) -> bool {
        BigUint::test_bit(self, index)
    }

    fn set_bit(&self, index: usize) -> Self::Output {
        BigUint::set_bit(self, index)
    }

    fn clear_bit(&self, index: usize) -> Self::Output {
        BigUint::clear_bit(self, index)
    }

    fn flip_bit(&self, index: usize) -> Self::Output {
        BigUint::flip_bit(self, index)
    }

    fn lowest_set_bit(&self) -> Option<usize> {
        BigUint::lowest_set_bit(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FixedBigUint;
    use crate::traits::{FromPrimitive, ToPrimitive};
    use alloc::string::ToString;

    #[test]
    fn radix_round_trip() {
        assert_eq!(
            BigUint::from_str_radix("ff", 16).unwrap(),
            BigUint::from(255_u16)
        );
    }

    #[test]
    fn external_units_are_little_endian() {
        let value = BigUint::from_le_bytes(&[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);

        assert_eq!(
            value.to_le_bytes(),
            [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
        assert_eq!(value.to_le_u32(), [0x5566_7788, 0x1122_3344]);
        assert_eq!(value.to_le_u64(), [0x1122_3344_5566_7788]);
    }

    #[test]
    fn number_theory_operations_match_known_values() {
        let three = BigUint::from(3_u8);
        let seven = BigUint::from(7_u8);

        assert_eq!(
            BigUint::from(48_u8).gcd(&BigUint::from(18_u8)),
            BigUint::from(6_u8)
        );
        assert_eq!(three.mod_inverse(&seven), Some(BigUint::from(5_u8)));
        assert_eq!(
            three.mod_pow(&BigUint::from(4_u8), &seven),
            BigUint::from(4_u8)
        );
        assert_eq!(
            three.mod_inverse(&BigUint::from(10_u8)),
            Some(BigUint::from(7_u8))
        );
    }

    #[test]
    fn bit_operations_match_the_le_value() {
        let value = BigUint::from(0b101100_u8);

        assert_eq!(value.bits(), 6);
        assert_eq!(value.bit_count(), 3);
        assert_eq!(value.lowest_set_bit(), Some(2));
        assert_eq!(value.set_bit(0), BigUint::from(0b101101_u8));
        assert_eq!(value.clear_bit(3), BigUint::from(0b100100_u8));
        assert_eq!(value.flip_bit(2), BigUint::from(0b101000_u8));
    }

    #[test]
    fn setting_or_flipping_a_low_bit_preserves_existing_high_limbs() {
        let high = Word::BITS as usize * 2 - 1;
        let value = BigUint::one().set_bit(high);

        let set = value.set_bit(0);
        assert!(set.test_bit(high));
        assert!(set.test_bit(0));
        assert_eq!(set.bits(), high + 1);

        let flipped = value.flip_bit(1);
        assert!(flipped.test_bit(high));
        assert!(flipped.test_bit(1));
        assert_eq!(flipped.bits(), high + 1);
    }

    #[test]
    fn conversion_writers_and_fixed_width_bridge_cover_success_and_errors() {
        let value = BigUint::from_le_u32(&[0x5566_7788, 0x1122_3344]);
        assert_eq!(
            value.as_limbs(),
            BigUint::from_le_u64(&[0x1122_3344_5566_7788]).as_limbs()
        );

        let mut bytes = [0_u8; 8];
        let mut words32 = [0_u32; 2];
        let mut words64 = [0_u64; 1];
        assert_eq!(value.write_le_bytes(&mut bytes), Ok(8));
        assert_eq!(value.write_le_u32(&mut words32), Ok(2));
        assert_eq!(value.write_le_u64(&mut words64), Ok(1));
        assert_eq!(BigUint::from(&bytes[..]), value);
        assert_eq!(BigUint::from(&words32[..]), value);
        assert_eq!(BigUint::from(&words64[..]), value);

        assert_eq!(
            value.write_le_bytes(&mut [0_u8; 7]),
            Err(ConversionError::BufferTooSmall)
        );
        assert_eq!(
            value.write_le_u32(&mut [0_u32; 1]),
            Err(ConversionError::BufferTooSmall)
        );
        assert_eq!(
            value.write_le_u64(&mut []),
            Err(ConversionError::BufferTooSmall)
        );

        type U = FixedBigUint<2>;
        let fixed = U::try_from(&value).expect("value fits");
        assert_eq!(BigUint::from(fixed), value);
        assert_eq!(
            FixedBigUint::<1>::try_from(&BigUint::from_le_u64(&[0, 1])),
            Err(ConversionError::InputTooLarge)
        );
    }

    #[test]
    fn bitwise_and_shift_operators_support_all_ownership_forms() {
        let left = BigUint::from(0b1100_u8);
        let right = BigUint::from(0b1010_u8);

        macro_rules! assert_forms {
            ($operator:tt, $expected:expr) => {{
                assert_eq!(&left $operator &right, BigUint::from($expected));
                assert_eq!(&left $operator right.clone(), BigUint::from($expected));
                assert_eq!(left.clone() $operator &right, BigUint::from($expected));
                assert_eq!(left.clone() $operator right.clone(), BigUint::from($expected));
            }};
        }

        assert_forms!(&, 0b1000_u8);
        assert_forms!(|, 0b1110_u8);
        assert_forms!(^, 0b0110_u8);
        assert_eq!(&left << 2, BigUint::from(48_u8));
        assert_eq!(left.clone() << 2, BigUint::from(48_u8));
        assert_eq!(&left >> 2, BigUint::from(3_u8));
        assert_eq!(left >> 2, BigUint::from(3_u8));

        let mut assigned = BigUint::from(0b1100_u8);
        assigned &= &BigUint::from(0b1010_u8);
        assigned |= BigUint::from(0b0011_u8);
        assigned ^= &BigUint::from(0b0101_u8);
        assigned <<= 2;
        assigned >>= 1;
        assert_eq!(assigned, BigUint::from(28_u8));
    }

    #[test]
    fn parsing_formatting_comparison_and_edge_bit_operations_are_covered() {
        assert!(BigUint::zero().is_zero());
        assert_eq!(BigUint::zero().to_str_radix(2), "0");
        assert_eq!(BigUint::from(255_u16).to_str_radix(16), "ff");
        assert_eq!(BigUint::from(42_u8).to_string(), "42");
        assert!(BigUint::from(2_u8) < BigUint::from(3_u8));

        assert_eq!(
            BigUint::from_str_radix("", 10),
            Err(ParseBigIntError::InvalidDigit)
        );
        assert_eq!(
            BigUint::from_str_radix("2", 2),
            Err(ParseBigIntError::InvalidDigit)
        );
        assert_eq!(
            BigUint::from_str_radix("-1", 10),
            Err(ParseBigIntError::NegativeUnsigned)
        );
        assert_eq!(
            BigUint::from_str_radix("1", 1),
            Err(ParseBigIntError::InvalidRadix)
        );

        let zero = BigUint::zero();
        assert!(!zero.test_bit(100));
        assert_eq!(zero.lowest_set_bit(), None);
        assert_eq!(zero.clear_bit(100), zero);
        assert!(zero.flip_bit(100).test_bit(100));
        assert_eq!(
            BigUint::from(0b1111_u8).and_not(&BigUint::from(0b0101_u8)),
            BigUint::from(0b1010_u8)
        );
    }

    #[test]
    fn conversion_traits_cover_dynamic_unsigned_specific_paths() {
        let value = BigUint::from(5_u8);
        assert_eq!(Pow::pow(value.clone(), &3_u32), BigUint::from(125_u8));
        assert_eq!(Pow::pow(&value, 3_u32), BigUint::from(125_u8));
        assert_eq!(Pow::pow(&value, &3_u32), BigUint::from(125_u8));

        assert_eq!(BigUint::from_i64(-1), None);
        assert_eq!(BigUint::from_i128(-1), None);
        assert_eq!(BigUint::from_u64(9), Some(BigUint::from(9_u8)));
        assert_eq!(
            BigUint::from_u128(u128::MAX),
            Some(BigUint::from(u128::MAX))
        );
        assert_eq!(BigUint::from(u128::MAX).to_i128(), None);
        assert_eq!(BigUint::from(u64::MAX).to_i64(), None);
        assert_eq!(BigUint::from(u64::MAX).to_u64(), Some(u64::MAX));
        assert_eq!(BigUint::from(u128::MAX).to_u128(), Some(u128::MAX));
        assert_eq!(BigUint::from_le_u64(&[0, 0, 1]).to_u128(), None);
    }

    #[test]
    #[should_panic(expected = "radix must be in 2..=36")]
    fn formatting_panics_for_an_invalid_radix() {
        let _ = BigUint::from(1_u8).to_str_radix(37);
    }

    #[test]
    #[should_panic(expected = "modulus must be non-zero")]
    fn modular_inverse_rejects_a_zero_modulus() {
        let _ = BigUint::from(1_u8).mod_inverse(&BigUint::zero());
    }

    #[test]
    #[should_panic(expected = "modulus must be non-zero")]
    fn modular_power_rejects_a_zero_modulus() {
        let _ = BigUint::from(1_u8).mod_pow(&BigUint::from(2_u8), &BigUint::zero());
    }
}
