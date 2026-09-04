//! Fixed-precision unsigned integers without allocation.

use core::ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr};

#[cfg(test)]
use crate::ConversionError;
use crate::arithmetic;
use crate::traits::{
    AndNot, BitOps, CheckedShl, CheckedShr, Gcd, ModInverse, ModPow, Num, One, Pow, Unsigned, Zero,
};
use crate::{Limb, ParseBigIntError, Word};

mod add;
mod array;
mod cmp;
mod div;
mod from;
mod mul;
mod sub;

/// An unsigned integer containing exactly `N` little-endian limbs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedBigUint<const N: usize> {
    limbs: [Limb; N],
}

impl<const N: usize> FixedBigUint<N> {
    pub(crate) const fn from_limbs(limbs: [Limb; N]) -> Self {
        Self { limbs }
    }

    pub(crate) const fn into_limbs(self) -> [Limb; N] {
        self.limbs
    }

    /// Returns zero.
    pub const fn zero() -> Self {
        Self {
            limbs: [Limb(0); N],
        }
    }

    /// Returns the maximum representable value.
    pub const fn max_value() -> Self {
        Self {
            limbs: [Limb(Word::MAX); N],
        }
    }

    /// Borrows all little-endian limbs, including high zero limbs.
    pub const fn as_limbs(&self) -> &[Limb; N] {
        &self.limbs
    }

    /// Returns whether this value is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|word| word.0 == 0)
    }

    /// Returns the greatest common divisor.
    pub fn gcd(&self, other: &Self) -> Self {
        Self {
            limbs: arithmetic::fixed_gcd(&self.limbs, &other.limbs),
        }
    }

    /// Returns the modular multiplicative inverse, when it exists.
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        arithmetic::fixed_mod_inverse(&self.limbs, &modulus.limbs).map(|limbs| Self { limbs })
    }

    /// Returns `self^exponent mod modulus`.
    pub fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        Self {
            limbs: arithmetic::fixed_mod_pow(&self.limbs, &exponent.limbs, &modulus.limbs),
        }
    }

    /// Returns the number of significant bits.
    pub fn bit_length(&self) -> usize {
        self.limbs
            .iter()
            .rposition(|word| word.0 != 0)
            .map_or(0, |index| {
                index * Word::BITS as usize
                    + (Word::BITS - self.limbs[index].0.leading_zeros()) as usize
            })
    }

    /// Counts all set bits.
    pub fn bit_count(&self) -> usize {
        self.limbs
            .iter()
            .map(|word| word.0.count_ones() as usize)
            .sum()
    }

    /// Tests bit `index`.
    pub fn test_bit(&self, index: usize) -> bool {
        self.limbs
            .get(index / Word::BITS as usize)
            .is_some_and(|word| word.0 >> (index % Word::BITS as usize) & 1 != 0)
    }

    /// Returns a value with bit `index` set.
    pub fn set_bit(&self, index: usize) -> Self {
        assert!(
            index < N * Word::BITS as usize,
            "bit index is outside fixed width"
        );
        let mut result = *self;
        result.limbs[index / Word::BITS as usize].0 |= (1 as Word) << (index % Word::BITS as usize);
        result
    }

    /// Returns a value with bit `index` cleared.
    pub fn clear_bit(&self, index: usize) -> Self {
        assert!(
            index < N * Word::BITS as usize,
            "bit index is outside fixed width"
        );
        let mut result = *self;
        result.limbs[index / Word::BITS as usize].0 &=
            !((1 as Word) << (index % Word::BITS as usize));
        result
    }

    /// Returns a value with bit `index` flipped.
    pub fn flip_bit(&self, index: usize) -> Self {
        assert!(
            index < N * Word::BITS as usize,
            "bit index is outside fixed width"
        );
        let mut result = *self;
        result.limbs[index / Word::BITS as usize].0 ^= (1 as Word) << (index % Word::BITS as usize);
        result
    }

    /// Returns the index of the least-significant set bit.
    pub fn lowest_set_bit(&self) -> Option<usize> {
        self.limbs
            .iter()
            .enumerate()
            .find(|(_, word)| word.0 != 0)
            .map(|(index, word)| index * Word::BITS as usize + word.0.trailing_zeros() as usize)
    }

    /// Returns `self & !other`.
    pub fn and_not(&self, other: &Self) -> Self {
        Self {
            limbs: core::array::from_fn(|index| Limb(self.limbs[index].0 & !other.limbs[index].0)),
        }
    }

    /// Parses an unsigned value in radix `2..=36`.
    pub fn from_str_radix(value: &str, radix: u32) -> Result<Self, ParseBigIntError> {
        if !(2..=36).contains(&radix) {
            return Err(ParseBigIntError::InvalidRadix);
        }
        let digits = value.strip_prefix('+').unwrap_or(value);
        if digits.starts_with('-') {
            return Err(ParseBigIntError::NegativeUnsigned);
        }
        if digits.is_empty() {
            return Err(ParseBigIntError::InvalidDigit);
        }

        let mut result = Self::zero();
        for byte in digits.bytes() {
            let digit = decode_digit(byte, radix)?;
            result = result
                .checked_mul_word(radix as Word)
                .and_then(|value| value.checked_add_word(digit as Word))
                .ok_or(ParseBigIntError::Overflow)?;
        }
        Ok(result)
    }

    fn checked_u128(&self) -> Option<u128> {
        let mut result = 0_u128;
        for (index, word) in self.limbs.iter().enumerate() {
            let shift = index * Word::BITS as usize;
            if shift >= 128 {
                if word.0 != 0 {
                    return None;
                }
            } else {
                result |= (word.0 as u128) << shift;
            }
        }
        Some(result)
    }
}

fn decode_digit(byte: u8, radix: u32) -> Result<u32, ParseBigIntError> {
    let digit = match byte {
        b'0'..=b'9' => u32::from(byte - b'0'),
        b'a'..=b'z' => u32::from(byte - b'a') + 10,
        b'A'..=b'Z' => u32::from(byte - b'A') + 10,
        _ => return Err(ParseBigIntError::InvalidDigit),
    };
    (digit < radix)
        .then_some(digit)
        .ok_or(ParseBigIntError::InvalidDigit)
}

impl<const N: usize> Default for FixedBigUint<N> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<const N: usize> BitAnd for FixedBigUint<N> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self {
            limbs: core::array::from_fn(|index| Limb(self.limbs[index].0 & rhs.limbs[index].0)),
        }
    }
}

impl<const N: usize> BitOr for FixedBigUint<N> {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            limbs: core::array::from_fn(|index| Limb(self.limbs[index].0 | rhs.limbs[index].0)),
        }
    }
}

impl<const N: usize> BitXor for FixedBigUint<N> {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self {
            limbs: core::array::from_fn(|index| Limb(self.limbs[index].0 ^ rhs.limbs[index].0)),
        }
    }
}

macro_rules! impl_borrowed_bitwise {
    ($trait:ident, $method:ident, $operator:tt) => {
        impl<const N: usize> $trait<&FixedBigUint<N>> for FixedBigUint<N> {
            type Output = FixedBigUint<N>;

            fn $method(self, rhs: &FixedBigUint<N>) -> Self::Output {
                self $operator *rhs
            }
        }

        impl<const N: usize> $trait<FixedBigUint<N>> for &FixedBigUint<N> {
            type Output = FixedBigUint<N>;

            fn $method(self, rhs: FixedBigUint<N>) -> Self::Output {
                *self $operator rhs
            }
        }

        impl<const N: usize> $trait<&FixedBigUint<N>> for &FixedBigUint<N> {
            type Output = FixedBigUint<N>;

            fn $method(self, rhs: &FixedBigUint<N>) -> Self::Output {
                *self $operator *rhs
            }
        }
    };
}

impl_borrowed_bitwise!(BitAnd, bitand, &);
impl_borrowed_bitwise!(BitOr, bitor, |);
impl_borrowed_bitwise!(BitXor, bitxor, ^);

impl<const N: usize> Not for FixedBigUint<N> {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self {
            limbs: self.limbs.map(|word| Limb(!word.0)),
        }
    }
}

impl<const N: usize> Not for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;

    fn not(self) -> Self::Output {
        !*self
    }
}

impl<const N: usize> Shl<usize> for FixedBigUint<N> {
    type Output = Self;

    fn shl(self, shift: usize) -> Self::Output {
        assert!(
            shift < N * Word::BITS as usize,
            "attempted to shift left with overflow"
        );
        let word_shift = shift / Word::BITS as usize;
        let bit_shift = shift % Word::BITS as usize;
        let limbs = core::array::from_fn(|index| {
            if index < word_shift {
                return Limb(0);
            }
            let source = index - word_shift;
            let mut value = self.limbs[source].0 << bit_shift;
            if bit_shift != 0 && source != 0 {
                value |= self.limbs[source - 1].0 >> (Word::BITS as usize - bit_shift);
            }
            Limb(value)
        });
        Self { limbs }
    }
}

impl<const N: usize> Shl<usize> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;

    fn shl(self, shift: usize) -> Self::Output {
        *self << shift
    }
}

impl<const N: usize> Shr<usize> for FixedBigUint<N> {
    type Output = Self;

    fn shr(self, shift: usize) -> Self::Output {
        assert!(
            shift < N * Word::BITS as usize,
            "attempted to shift right with overflow"
        );
        let word_shift = shift / Word::BITS as usize;
        let bit_shift = shift % Word::BITS as usize;
        let limbs = core::array::from_fn(|index| {
            let source = index + word_shift;
            if source >= N {
                return Limb(0);
            }
            let mut value = self.limbs[source].0 >> bit_shift;
            if bit_shift != 0 && source + 1 < N {
                value |= self.limbs[source + 1].0 << (Word::BITS as usize - bit_shift);
            }
            Limb(value)
        });
        Self { limbs }
    }
}

impl<const N: usize> Shr<usize> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;

    fn shr(self, shift: usize) -> Self::Output {
        *self >> shift
    }
}

impl<const N: usize> CheckedShl for FixedBigUint<N> {
    fn checked_shl(&self, rhs: u32) -> Option<Self> {
        let shift = rhs as usize;
        let width = N * Word::BITS as usize;
        if shift >= width || self.bit_length().saturating_add(shift) > width {
            return None;
        }
        Some(*self << shift)
    }
}

impl<const N: usize> CheckedShr for FixedBigUint<N> {
    fn checked_shr(&self, rhs: u32) -> Option<Self> {
        let shift = rhs as usize;
        (shift < N * Word::BITS as usize).then(|| *self >> shift)
    }
}

impl<const N: usize> Zero for FixedBigUint<N> {
    fn zero() -> Self {
        Self::zero()
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}

impl<const N: usize> One for FixedBigUint<N> {
    fn one() -> Self {
        Self::from(1_u8)
    }
}

impl<const N: usize> Num for FixedBigUint<N> {
    type FromStrRadixErr = ParseBigIntError;

    fn from_str_radix(value: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        Self::from_str_radix(value, radix)
    }
}

impl<const N: usize> Unsigned for FixedBigUint<N> {}

impl<const N: usize> Pow<u32> for FixedBigUint<N> {
    type Output = Self;

    fn pow(self, mut exponent: u32) -> Self::Output {
        let mut base = self;
        let mut result = Self::one();
        while exponent != 0 {
            if exponent & 1 != 0 {
                result *= base;
            }
            exponent >>= 1;
            if exponent != 0 {
                base *= base;
            }
        }
        result
    }
}

impl<const N: usize> Pow<&u32> for FixedBigUint<N> {
    type Output = Self;

    fn pow(self, exponent: &u32) -> Self::Output {
        Pow::pow(self, *exponent)
    }
}

impl<const N: usize> Pow<u32> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;

    fn pow(self, exponent: u32) -> Self::Output {
        Pow::pow(*self, exponent)
    }
}

impl<const N: usize> Pow<&u32> for &FixedBigUint<N> {
    type Output = FixedBigUint<N>;

    fn pow(self, exponent: &u32) -> Self::Output {
        Pow::pow(*self, *exponent)
    }
}

impl<const N: usize> Gcd for FixedBigUint<N> {
    type Output = Self;

    fn gcd(&self, rhs: &Self) -> Self::Output {
        FixedBigUint::gcd(self, rhs)
    }
}

impl<const N: usize> ModInverse for FixedBigUint<N> {
    type Output = Self;

    fn mod_inverse(&self, modulus: &Self) -> Option<Self::Output> {
        FixedBigUint::mod_inverse(self, modulus)
    }
}

impl<const N: usize> ModPow for FixedBigUint<N> {
    type Output = Self;

    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self::Output {
        FixedBigUint::mod_pow(self, exponent, modulus)
    }
}

impl<const N: usize> BitOps for FixedBigUint<N> {
    type Output = Self;

    fn bit_length(&self) -> usize {
        FixedBigUint::bit_length(self)
    }

    fn bit_count(&self) -> usize {
        FixedBigUint::bit_count(self)
    }

    fn test_bit(&self, index: usize) -> bool {
        FixedBigUint::test_bit(self, index)
    }

    fn set_bit(&self, index: usize) -> Self::Output {
        FixedBigUint::set_bit(self, index)
    }

    fn clear_bit(&self, index: usize) -> Self::Output {
        FixedBigUint::clear_bit(self, index)
    }

    fn flip_bit(&self, index: usize) -> Self::Output {
        FixedBigUint::flip_bit(self, index)
    }

    fn lowest_set_bit(&self) -> Option<usize> {
        FixedBigUint::lowest_set_bit(self)
    }
}

impl<const N: usize> AndNot for FixedBigUint<N> {
    type Output = Self;

    fn and_not(&self, rhs: &Self) -> Self::Output {
        FixedBigUint::and_not(self, rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{FromPrimitive, ToPrimitive};

    type U128 = FixedBigUint<{ 128 / Word::BITS as usize }>;

    #[test]
    fn external_units_are_full_width_and_little_endian() {
        let value = U128::from_le_u64(&[0x1122_3344_5566_7788]).unwrap();
        let mut bytes = [0_u8; 16];
        let mut words32 = [0_u32; 4];
        let mut words64 = [0_u64; 2];

        assert_eq!(value.write_le_bytes(&mut bytes), Ok(16));
        assert_eq!(
            &bytes[..8],
            &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
        assert_eq!(value.write_le_u32(&mut words32), Ok(4));
        assert_eq!(words32, [0x5566_7788, 0x1122_3344, 0, 0]);
        assert_eq!(value.write_le_u64(&mut words64), Ok(2));
        assert_eq!(words64, [0x1122_3344_5566_7788, 0]);
    }

    #[test]
    fn modular_operations_do_not_allocate_or_overflow_intermediates() {
        let three = U128::from(3_u8);
        let seven = U128::from(7_u8);

        assert_eq!(U128::from(48_u8).gcd(&U128::from(18_u8)), U128::from(6_u8));
        assert_eq!(three.mod_inverse(&seven), Some(U128::from(5_u8)));
        assert_eq!(
            three.mod_inverse(&U128::from(10_u8)),
            Some(U128::from(7_u8))
        );
        assert_eq!(three.mod_pow(&U128::from(4_u8), &seven), U128::from(4_u8));

        let max = U128::max_value();
        assert_eq!(
            U128::from(2_u8).mod_inverse(&max),
            Some(U128::from(1_u8) << 127)
        );
        assert_eq!(
            (max - U128::from(1_u8)).mod_pow(&U128::from(2_u8), &max),
            U128::from(1_u8)
        );
    }

    #[test]
    fn public_state_bit_and_parsing_methods_cover_normal_and_error_paths() {
        assert!(U128::default().is_zero());
        assert_eq!(
            U128::zero().as_limbs(),
            &[Limb(0); 128 / Word::BITS as usize]
        );
        assert_eq!(U128::max_value().bit_length(), 128);

        let value = U128::from(0b1010_u8);
        assert_eq!(value.bit_count(), 2);
        assert!(value.test_bit(3));
        assert!(!value.test_bit(128));
        assert_eq!(value.set_bit(0), U128::from(0b1011_u8));
        assert_eq!(value.clear_bit(3), U128::from(0b0010_u8));
        assert_eq!(value.flip_bit(1), U128::from(0b1000_u8));
        assert_eq!(value.lowest_set_bit(), Some(1));
        assert_eq!(U128::zero().lowest_set_bit(), None);
        assert_eq!(value.and_not(&U128::from(0b0011_u8)), U128::from(8_u8));

        assert_eq!(U128::from_str_radix("+FF", 16), Ok(U128::from(255_u16)));
        assert_eq!(
            U128::from_str_radix("-1", 10),
            Err(ParseBigIntError::NegativeUnsigned)
        );
        assert_eq!(
            U128::from_str_radix("", 10),
            Err(ParseBigIntError::InvalidDigit)
        );
        assert_eq!(
            U128::from_str_radix("?", 10),
            Err(ParseBigIntError::InvalidDigit)
        );
        assert_eq!(
            U128::from_str_radix("2", 2),
            Err(ParseBigIntError::InvalidDigit)
        );
        assert_eq!(
            U128::from_str_radix("1", 1),
            Err(ParseBigIntError::InvalidRadix)
        );
        assert_eq!(
            FixedBigUint::<1>::from_str_radix("1".repeat(Word::BITS as usize + 1).as_str(), 2),
            Err(ParseBigIntError::Overflow)
        );
    }

    #[test]
    fn decoders_try_from_and_writers_cover_each_error_path() {
        assert_eq!(U128::from_le_bytes(&[1]), Ok(U128::from(1_u8)));
        assert_eq!(U128::from_le_u32(&[1]), Ok(U128::from(1_u8)));
        assert_eq!(U128::from_le_u64(&[1]), Ok(U128::from(1_u8)));
        assert_eq!(U128::try_from(&[1_u8][..]), Ok(U128::from(1_u8)));
        assert_eq!(U128::try_from(&[1_u32][..]), Ok(U128::from(1_u8)));
        assert_eq!(U128::try_from(&[1_u64][..]), Ok(U128::from(1_u8)));

        assert_eq!(
            FixedBigUint::<0>::from_le_bytes(&[1]),
            Err(ConversionError::InputTooLarge)
        );
        assert_eq!(
            FixedBigUint::<0>::from_le_u32(&[1]),
            Err(ConversionError::InputTooLarge)
        );
        assert_eq!(
            FixedBigUint::<0>::from_le_u64(&[1]),
            Err(ConversionError::InputTooLarge)
        );
        assert_eq!(
            U128::zero().write_le_bytes(&mut [0_u8; 15]),
            Err(ConversionError::BufferTooSmall)
        );
        assert_eq!(
            U128::zero().write_le_u32(&mut [0_u32; 3]),
            Err(ConversionError::BufferTooSmall)
        );
        assert_eq!(
            U128::zero().write_le_u64(&mut [0_u64; 1]),
            Err(ConversionError::BufferTooSmall)
        );
    }

    #[test]
    fn bitwise_not_and_shift_operator_forms_are_all_available() {
        let left = U128::from(0b1100_u8);
        let right = U128::from(0b1010_u8);

        macro_rules! assert_forms {
            ($operator:tt, $expected:expr) => {{
                assert_eq!(left $operator right, U128::from($expected));
                assert_eq!(left $operator &right, U128::from($expected));
                assert_eq!(&left $operator right, U128::from($expected));
                assert_eq!(&left $operator &right, U128::from($expected));
            }};
        }

        assert_forms!(&, 0b1000_u8);
        assert_forms!(|, 0b1110_u8);
        assert_forms!(^, 0b0110_u8);
        assert_eq!(!left, !&left);
        assert_eq!(left << 2, U128::from(48_u8));
        assert_eq!(&left << 2, U128::from(48_u8));
        assert_eq!(left >> 2, U128::from(3_u8));
        assert_eq!(&left >> 2, U128::from(3_u8));
    }

    #[test]
    fn numeric_trait_specific_paths_are_covered() {
        let value = U128::from(5_u8);
        assert_eq!(Pow::pow(value, 3_u32), U128::from(125_u8));
        assert_eq!(Pow::pow(value, &3_u32), U128::from(125_u8));
        assert_eq!(Pow::pow(&value, 3_u32), U128::from(125_u8));
        assert_eq!(Pow::pow(&value, &3_u32), U128::from(125_u8));
        assert_eq!(U128::from_i64(-1), None);
        assert_eq!(U128::from_i128(-1), None);
        assert_eq!(U128::from_u64(9), Some(U128::from(9_u8)));
        assert_eq!(U128::from_u128(u128::MAX), Some(U128::from(u128::MAX)));
        assert_eq!(U128::from(u64::MAX).to_i64(), None);
        assert_eq!(U128::from(u128::MAX).to_i128(), None);
        assert_eq!(U128::from(u64::MAX).to_u64(), Some(u64::MAX));
        assert_eq!(U128::from(u128::MAX).to_u128(), Some(u128::MAX));
    }

    #[test]
    #[should_panic(expected = "bit index is outside fixed width")]
    fn set_bit_rejects_out_of_range_index() {
        let _ = U128::zero().set_bit(128);
    }

    #[test]
    #[should_panic(expected = "bit index is outside fixed width")]
    fn clear_bit_rejects_out_of_range_index() {
        let _ = U128::zero().clear_bit(128);
    }

    #[test]
    #[should_panic(expected = "bit index is outside fixed width")]
    fn flip_bit_rejects_out_of_range_index() {
        let _ = U128::zero().flip_bit(128);
    }

    #[test]
    #[should_panic(expected = "attempted to shift left with overflow")]
    fn left_shift_rejects_width_or_larger() {
        let _ = U128::from(1_u8) << 128;
    }

    #[test]
    #[should_panic(expected = "attempted to shift right with overflow")]
    fn right_shift_rejects_width_or_larger() {
        let _ = U128::from(1_u8) >> 128;
    }

    #[test]
    #[should_panic(expected = "modulus must be non-zero")]
    fn modular_inverse_rejects_zero() {
        let _ = U128::from(1_u8).mod_inverse(&U128::zero());
    }

    #[test]
    #[should_panic(expected = "modulus must be non-zero")]
    fn modular_power_rejects_zero() {
        let _ = U128::from(1_u8).mod_pow(&U128::from(2_u8), &U128::zero());
    }
}
