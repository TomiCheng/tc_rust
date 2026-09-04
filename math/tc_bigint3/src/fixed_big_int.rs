//! Fixed-precision signed integers without allocation.

use core::cmp::Ordering;
use core::fmt;
use core::ops::{
    BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Neg, Not, Shl, ShlAssign, Shr,
    ShrAssign,
};

#[cfg(test)]
use crate::ConversionError;
use crate::arithmetic;
use crate::traits::{
    AndNot, BitOps, Bounded, CheckedNeg, CheckedShl, CheckedShr, Gcd, ModInverse, ModPow, Num, One,
    Pow, Signed, ToPrimitive, WrappingNeg, Zero,
};
use crate::{FixedBigUint, Limb, ParseBigIntError, Word};

mod add;
mod array;
mod cmp;
mod div;
mod from;
mod mul;
mod sub;

/// A signed two's-complement integer containing exactly `N` little-endian limbs.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FixedBigInt<const N: usize> {
    limbs: [Limb; N],
}

impl<const N: usize> FixedBigInt<N> {
    /// Lowest representable value.
    pub const MIN: Self = {
        let mut limbs = [Limb(0); N];
        if N != 0 {
            limbs[N - 1] = Limb(1 << (Word::BITS - 1));
        }
        Self { limbs }
    };

    /// Highest representable value.
    pub const MAX: Self = {
        let mut limbs = [Limb(Word::MAX); N];
        if N != 0 {
            limbs[N - 1] = Limb(Word::MAX >> 1);
        }
        Self { limbs }
    };

    pub(crate) const fn from_limbs(limbs: [Limb; N]) -> Self {
        Self { limbs }
    }

    /// Returns zero.
    pub const fn zero() -> Self {
        Self::from_limbs([Limb(0); N])
    }

    /// Returns the lowest representable signed value.
    pub const fn min_value() -> Self {
        Self::MIN
    }

    /// Returns the highest representable signed value.
    pub const fn max_value() -> Self {
        Self::MAX
    }

    /// Borrows all little-endian two's-complement limbs.
    pub const fn as_limbs(&self) -> &[Limb; N] {
        &self.limbs
    }

    /// Returns whether the value is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|word| word.0 == 0)
    }

    /// Returns whether the sign bit is set.
    pub fn is_negative(&self) -> bool {
        arithmetic::fixed_is_negative(&self.limbs)
    }

    /// Returns the absolute value, panicking when called on `MIN`.
    pub fn abs(&self) -> Self {
        if self.is_negative() { -*self } else { *self }
    }

    /// Returns the non-negative greatest common divisor as an unsigned value.
    pub fn gcd(&self, other: &Self) -> FixedBigUint<N> {
        FixedBigUint::from_limbs(arithmetic::fixed_gcd(&self.magnitude(), &other.magnitude()))
    }

    /// Returns the modular multiplicative inverse, when it exists.
    pub fn mod_inverse(&self, modulus: &Self) -> Option<Self> {
        assert!(modulus.is_positive(), "modulus must be positive");
        let value = self.rem_euclid(modulus);
        arithmetic::fixed_mod_inverse(&value.limbs, &modulus.limbs)
            .and_then(|limbs| Self::from_sign_magnitude(false, limbs))
    }

    /// Returns `self^exponent mod modulus`.
    ///
    /// Negative exponents use a modular inverse. The modulus must be positive.
    pub fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        assert!(modulus.is_positive(), "modulus must be positive");
        let base = self.rem_euclid(modulus);
        let result = arithmetic::fixed_mod_pow(&base.limbs, &exponent.magnitude(), &modulus.limbs);
        let result = Self::from_sign_magnitude(false, result)
            .expect("a modular result is smaller than the positive modulus");
        if exponent.is_negative() {
            result
                .mod_inverse(modulus)
                .expect("base is not invertible for a negative exponent")
        } else {
            result
        }
    }

    /// Returns the significant bit length excluding sign extension.
    pub fn bit_length(&self) -> usize {
        self.limbs
            .iter()
            .rposition(|word| {
                if self.is_negative() {
                    word.0 != Word::MAX
                } else {
                    word.0 != 0
                }
            })
            .map_or(0, |index| {
                let word = if self.is_negative() {
                    !self.limbs[index].0
                } else {
                    self.limbs[index].0
                };
                index * Word::BITS as usize + (Word::BITS - word.leading_zeros()) as usize
            })
    }

    /// Counts bits which differ from sign extension.
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

    /// Counts zero bits from the most-significant end of the fixed-width
    /// two's-complement representation.
    pub fn leading_zeros(&self) -> usize {
        self.limbs
            .iter()
            .rev()
            .try_fold(0_usize, |count, limb| {
                if limb.0 == 0 {
                    Ok(count + Word::BITS as usize)
                } else {
                    Err(count + limb.0.leading_zeros() as usize)
                }
            })
            .unwrap_or_else(|count| count)
    }

    /// Tests bit `index`, including mathematical sign extension above the width.
    pub fn test_bit(&self, index: usize) -> bool {
        self.limbs
            .get(index / Word::BITS as usize)
            .map_or(self.is_negative(), |word| {
                word.0 >> (index % Word::BITS as usize) & 1 != 0
            })
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

    /// Parses a signed value in radix `2..=36`.
    pub fn from_str_radix(value: &str, radix: u32) -> Result<Self, ParseBigIntError> {
        let (negative, digits) = if let Some(digits) = value.strip_prefix('-') {
            (true, digits)
        } else {
            (false, value.strip_prefix('+').unwrap_or(value))
        };
        let magnitude = FixedBigUint::<N>::from_str_radix(digits, radix)?;
        Self::from_sign_magnitude(negative, magnitude.into_limbs())
            .ok_or(ParseBigIntError::Overflow)
    }

    /// Formats this value in radix `2..=36`.
    #[cfg(feature = "alloc")]
    pub fn to_str_radix(&self, radix: u32) -> alloc::string::String {
        crate::BigInt::from(*self).to_str_radix(radix)
    }

    fn magnitude(&self) -> [Limb; N] {
        arithmetic::fixed_abs(&self.limbs)
    }

    fn from_sign_magnitude(negative: bool, magnitude: [Limb; N]) -> Option<Self> {
        let min_magnitude = Self::min_value().limbs;
        if negative {
            if arithmetic::fixed_cmp(&magnitude, &min_magnitude) == Ordering::Greater {
                return None;
            }
            Some(Self {
                limbs: arithmetic::fixed_wrapping_neg(&magnitude),
            })
        } else {
            if arithmetic::fixed_is_negative(&magnitude) {
                return None;
            }
            Some(Self { limbs: magnitude })
        }
    }

    fn checked_i128(&self) -> Option<i128> {
        let magnitude = FixedBigUint::from_limbs(self.magnitude()).to_u128()?;
        if self.is_negative() {
            if magnitude == 1_u128 << 127 {
                Some(i128::MIN)
            } else {
                i128::try_from(magnitude).ok().map(|value| -value)
            }
        } else {
            i128::try_from(magnitude).ok()
        }
    }
}

impl<const N: usize> Default for FixedBigInt<N> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<const N: usize> Bounded for FixedBigInt<N> {
    const MIN: Self = Self::MIN;
    const MAX: Self = Self::MAX;
}

impl<const N: usize> fmt::Display for FixedBigInt<N> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::format::fmt_fixed(&self.magnitude(), self.is_negative(), 10, false, "", output)
    }
}

impl<const N: usize> fmt::Debug for FixedBigInt<N> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, output)
    }
}

macro_rules! impl_fixed_int_format {
    ($trait:ident, $radix:expr, $uppercase:expr, $prefix:expr) => {
        impl<const N: usize> fmt::$trait for FixedBigInt<N> {
            fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
                crate::format::fmt_fixed(
                    &self.magnitude(),
                    self.is_negative(),
                    $radix,
                    $uppercase,
                    $prefix,
                    output,
                )
            }
        }
    };
}

impl_fixed_int_format!(Binary, 2, false, "0b");
impl_fixed_int_format!(Octal, 8, false, "0o");
impl_fixed_int_format!(LowerHex, 16, false, "0x");
impl_fixed_int_format!(UpperHex, 16, true, "0x");

impl<const N: usize> Neg for FixedBigInt<N> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        assert!(
            self != Self::min_value(),
            "attempted to negate with overflow"
        );
        Self {
            limbs: arithmetic::fixed_wrapping_neg(&self.limbs),
        }
    }
}

impl<const N: usize> Neg for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;

    fn neg(self) -> Self::Output {
        -*self
    }
}

impl<const N: usize> CheckedNeg for FixedBigInt<N> {
    fn checked_neg(&self) -> Option<Self> {
        (*self != Self::min_value()).then(|| Self {
            limbs: arithmetic::fixed_wrapping_neg(&self.limbs),
        })
    }
}

impl<const N: usize> WrappingNeg for FixedBigInt<N> {
    fn wrapping_neg(&self) -> Self {
        Self {
            limbs: arithmetic::fixed_wrapping_neg(&self.limbs),
        }
    }
}

impl<const N: usize> BitAnd for FixedBigInt<N> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self {
            limbs: core::array::from_fn(|index| Limb(self.limbs[index].0 & rhs.limbs[index].0)),
        }
    }
}

impl<const N: usize> BitOr for FixedBigInt<N> {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            limbs: core::array::from_fn(|index| Limb(self.limbs[index].0 | rhs.limbs[index].0)),
        }
    }
}

impl<const N: usize> BitXor for FixedBigInt<N> {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self {
            limbs: core::array::from_fn(|index| Limb(self.limbs[index].0 ^ rhs.limbs[index].0)),
        }
    }
}

macro_rules! impl_borrowed_bitwise {
    ($trait:ident, $method:ident, $operator:tt) => {
        impl<const N: usize> $trait<&FixedBigInt<N>> for FixedBigInt<N> {
            type Output = FixedBigInt<N>;

            fn $method(self, rhs: &FixedBigInt<N>) -> Self::Output {
                self $operator *rhs
            }
        }

        impl<const N: usize> $trait<FixedBigInt<N>> for &FixedBigInt<N> {
            type Output = FixedBigInt<N>;

            fn $method(self, rhs: FixedBigInt<N>) -> Self::Output {
                *self $operator rhs
            }
        }

        impl<const N: usize> $trait<&FixedBigInt<N>> for &FixedBigInt<N> {
            type Output = FixedBigInt<N>;

            fn $method(self, rhs: &FixedBigInt<N>) -> Self::Output {
                *self $operator *rhs
            }
        }
    };
}

impl_borrowed_bitwise!(BitAnd, bitand, &);
impl_borrowed_bitwise!(BitOr, bitor, |);
impl_borrowed_bitwise!(BitXor, bitxor, ^);

macro_rules! impl_fixed_int_bitwise_assign {
    ($trait:ident, $method:ident, $operator:tt) => {
        impl<const N: usize> $trait<&FixedBigInt<N>> for FixedBigInt<N> {
            fn $method(&mut self, rhs: &FixedBigInt<N>) {
                *self = *self $operator *rhs;
            }
        }

        impl<const N: usize> $trait for FixedBigInt<N> {
            fn $method(&mut self, rhs: Self) {
                self.$method(&rhs);
            }
        }
    };
}

impl_fixed_int_bitwise_assign!(BitAndAssign, bitand_assign, &);
impl_fixed_int_bitwise_assign!(BitOrAssign, bitor_assign, |);
impl_fixed_int_bitwise_assign!(BitXorAssign, bitxor_assign, ^);

impl<const N: usize> Not for FixedBigInt<N> {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self {
            limbs: self.limbs.map(|word| Limb(!word.0)),
        }
    }
}

impl<const N: usize> Not for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;

    fn not(self) -> Self::Output {
        !*self
    }
}

impl<const N: usize> Shl<usize> for FixedBigInt<N> {
    type Output = Self;

    fn shl(self, shift: usize) -> Self::Output {
        assert!(
            shift < N * Word::BITS as usize,
            "attempted to shift left with overflow"
        );
        let unsigned = FixedBigUint::from_limbs(self.limbs) << shift;
        Self {
            limbs: unsigned.into_limbs(),
        }
    }
}

impl<const N: usize> Shl<usize> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;

    fn shl(self, shift: usize) -> Self::Output {
        *self << shift
    }
}

impl<const N: usize> Shr<usize> for FixedBigInt<N> {
    type Output = Self;

    fn shr(self, shift: usize) -> Self::Output {
        assert!(
            shift < N * Word::BITS as usize,
            "attempted to shift right with overflow"
        );
        let word_shift = shift / Word::BITS as usize;
        let bit_shift = shift % Word::BITS as usize;
        let extension = if self.is_negative() { Word::MAX } else { 0 };
        let limbs = core::array::from_fn(|index| {
            let source = index + word_shift;
            let low = self.limbs.get(source).map_or(extension, |word| word.0);
            let mut value = low >> bit_shift;
            if bit_shift != 0 {
                let high = self.limbs.get(source + 1).map_or(extension, |word| word.0);
                value |= high << (Word::BITS as usize - bit_shift);
            }
            Limb(value)
        });
        Self { limbs }
    }
}

impl<const N: usize> Shr<usize> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;

    fn shr(self, shift: usize) -> Self::Output {
        *self >> shift
    }
}

impl<const N: usize> CheckedShl for FixedBigInt<N> {
    fn checked_shl(&self, rhs: u32) -> Option<Self> {
        let shift = rhs as usize;
        let width = N * Word::BITS as usize;
        if shift >= width {
            return None;
        }
        let shifted = *self << shift;
        ((shifted >> shift) == *self).then_some(shifted)
    }
}

impl<const N: usize> CheckedShr for FixedBigInt<N> {
    fn checked_shr(&self, rhs: u32) -> Option<Self> {
        let shift = rhs as usize;
        (shift < N * Word::BITS as usize).then(|| *self >> shift)
    }
}

impl<const N: usize> ShlAssign<usize> for FixedBigInt<N> {
    fn shl_assign(&mut self, rhs: usize) {
        *self = *self << rhs;
    }
}

impl<const N: usize> ShrAssign<usize> for FixedBigInt<N> {
    fn shr_assign(&mut self, rhs: usize) {
        *self = *self >> rhs;
    }
}

impl<const N: usize> Zero for FixedBigInt<N> {
    fn zero() -> Self {
        Self::zero()
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}

impl<const N: usize> One for FixedBigInt<N> {
    fn one() -> Self {
        Self::from(1_i8)
    }
}

impl<const N: usize> Num for FixedBigInt<N> {
    type FromStrRadixErr = ParseBigIntError;

    fn from_str_radix(value: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        Self::from_str_radix(value, radix)
    }
}

impl<const N: usize> Signed for FixedBigInt<N> {
    fn abs(&self) -> Self {
        self.abs()
    }

    fn abs_sub(&self, other: &Self) -> Self {
        if self <= other {
            Self::zero()
        } else {
            *self - *other
        }
    }

    fn signum(&self) -> Self {
        if self.is_negative() {
            Self::from(-1_i8)
        } else if self.is_zero() {
            Self::zero()
        } else {
            Self::from(1_i8)
        }
    }

    fn is_positive(&self) -> bool {
        !self.is_zero() && !self.is_negative()
    }

    fn is_negative(&self) -> bool {
        self.is_negative()
    }
}

impl<const N: usize> Pow<u32> for FixedBigInt<N> {
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

impl<const N: usize> Pow<&u32> for FixedBigInt<N> {
    type Output = Self;

    fn pow(self, exponent: &u32) -> Self::Output {
        Pow::pow(self, *exponent)
    }
}

impl<const N: usize> Pow<u32> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;

    fn pow(self, exponent: u32) -> Self::Output {
        Pow::pow(*self, exponent)
    }
}

impl<const N: usize> Pow<&u32> for &FixedBigInt<N> {
    type Output = FixedBigInt<N>;

    fn pow(self, exponent: &u32) -> Self::Output {
        Pow::pow(*self, *exponent)
    }
}

impl<const N: usize> Gcd for FixedBigInt<N> {
    type Output = FixedBigUint<N>;

    fn gcd(&self, rhs: &Self) -> Self::Output {
        FixedBigInt::gcd(self, rhs)
    }
}

impl<const N: usize> ModInverse for FixedBigInt<N> {
    type Output = Self;

    fn mod_inverse(&self, modulus: &Self) -> Option<Self::Output> {
        FixedBigInt::mod_inverse(self, modulus)
    }
}

impl<const N: usize> ModPow for FixedBigInt<N> {
    type Output = Self;

    fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self::Output {
        FixedBigInt::mod_pow(self, exponent, modulus)
    }
}

impl<const N: usize> BitOps for FixedBigInt<N> {
    type Output = Self;

    fn bit_length(&self) -> usize {
        FixedBigInt::bit_length(self)
    }

    fn bit_count(&self) -> usize {
        FixedBigInt::bit_count(self)
    }

    fn test_bit(&self, index: usize) -> bool {
        FixedBigInt::test_bit(self, index)
    }

    fn set_bit(&self, index: usize) -> Self::Output {
        FixedBigInt::set_bit(self, index)
    }

    fn clear_bit(&self, index: usize) -> Self::Output {
        FixedBigInt::clear_bit(self, index)
    }

    fn flip_bit(&self, index: usize) -> Self::Output {
        FixedBigInt::flip_bit(self, index)
    }

    fn lowest_set_bit(&self) -> Option<usize> {
        FixedBigInt::lowest_set_bit(self)
    }
}

impl<const N: usize> AndNot for FixedBigInt<N> {
    type Output = Self;

    fn and_not(&self, rhs: &Self) -> Self::Output {
        FixedBigInt::and_not(self, rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{FromPrimitive, ToPrimitive};

    type I128 = FixedBigInt<{ 128 / Word::BITS as usize }>;

    #[test]
    fn fixed_signed_io_is_twos_complement_and_little_endian() {
        let value = I128::from(-2_i8);
        let mut bytes = [0_u8; 16];
        let mut words32 = [0_u32; 4];
        let mut words64 = [0_u64; 2];

        assert_eq!(value.write_le_bytes(&mut bytes), Ok(16));
        assert_eq!(
            bytes,
            [
                0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff
            ]
        );
        assert_eq!(value.write_le_u32(&mut words32), Ok(4));
        assert_eq!(words32, [0xffff_fffe, u32::MAX, u32::MAX, u32::MAX]);
        assert_eq!(value.write_le_u64(&mut words64), Ok(2));
        assert_eq!(words64, [u64::MAX - 1, u64::MAX]);
    }

    #[test]
    fn right_shift_sign_extends() {
        assert_eq!((I128::from(-3_i8) >> 1).to_i64(), Some(-2));
        assert_eq!((I128::from(3_i8) >> 1).to_i64(), Some(1));
    }

    #[test]
    fn signed_number_theory_uses_unsigned_gcd_and_positive_modulus() {
        let three = I128::from(3_i8);
        let seven = I128::from(7_i8);

        assert_eq!(
            I128::from(-12_i8).gcd(&I128::from(18_i8)),
            FixedBigUint::from(6_u8)
        );
        assert_eq!(I128::from(-7_i8).rem_euclid(&three), I128::from(2_i8));
        assert_eq!(three.mod_inverse(&seven), Some(I128::from(5_i8)));
        assert_eq!(three.mod_pow(&I128::from(4_i8), &seven), I128::from(4_i8));
        assert_eq!(three.mod_pow(&I128::from(-1_i8), &seven), I128::from(5_i8));
    }

    #[test]
    fn public_state_bit_and_parsing_methods_cover_signed_cases() {
        assert!(I128::default().is_zero());
        assert!(I128::min_value().is_negative());
        assert!(!I128::max_value().is_negative());
        assert_eq!(
            I128::zero().as_limbs(),
            &[Limb(0); 128 / Word::BITS as usize]
        );
        assert_eq!(I128::from(-7_i8).abs(), I128::from(7_i8));

        let value = I128::from(0b1010_i8);
        assert_eq!(value.bit_length(), 4);
        assert_eq!(value.bit_count(), 2);
        assert!(value.test_bit(3));
        assert!(!value.test_bit(128));
        assert!(I128::from(-1_i8).test_bit(128));
        assert_eq!(value.set_bit(0), I128::from(0b1011_i8));
        assert_eq!(value.clear_bit(3), I128::from(0b0010_i8));
        assert_eq!(value.flip_bit(1), I128::from(0b1000_i8));
        assert_eq!(value.lowest_set_bit(), Some(1));
        assert_eq!(I128::zero().lowest_set_bit(), None);
        assert_eq!(value.and_not(&I128::from(0b0011_i8)), I128::from(8_i8));

        assert_eq!(I128::from_str_radix("+7F", 16), Ok(I128::from(127_i8)));
        assert_eq!(I128::from_str_radix("-7F", 16), Ok(I128::from(-127_i8)));
        assert_eq!(
            I128::from_str_radix("", 10),
            Err(ParseBigIntError::InvalidDigit)
        );
        assert_eq!(
            FixedBigInt::<1>::from_str_radix("1".repeat(Word::BITS as usize).as_str(), 2),
            Err(ParseBigIntError::Overflow)
        );
    }

    #[test]
    fn bounds_default_and_leading_zeros_are_available() {
        assert_eq!(I128::MIN, I128::min_value());
        assert_eq!(I128::MAX, I128::max_value());
        assert_eq!(I128::default(), I128::zero());
        assert_eq!(I128::zero().leading_zeros(), 128);
        assert_eq!(I128::from(1_i8).leading_zeros(), 127);
        assert_eq!(I128::from(-1_i8).leading_zeros(), 0);
    }

    #[test]
    fn signed_unsigned_decoders_try_from_and_writer_errors_are_covered() {
        assert_eq!(I128::from_le_bytes(&[0xfe]), Ok(I128::from(-2_i8)));
        assert_eq!(I128::from_le_u32(&[u32::MAX - 1]), Ok(I128::from(-2_i8)));
        assert_eq!(I128::from_le_u64(&[u64::MAX - 1]), Ok(I128::from(-2_i8)));
        assert_eq!(
            I128::from_unsigned_le_bytes(&[0xfe]),
            Ok(I128::from(254_u16))
        );
        assert_eq!(
            I128::from_unsigned_le_u32(&[u32::MAX]),
            Ok(I128::from(u32::MAX))
        );
        assert_eq!(
            I128::from_unsigned_le_u64(&[u64::MAX]),
            Ok(I128::from(u64::MAX))
        );
        assert_eq!(I128::try_from(&[0xfe_u8][..]), Ok(I128::from(-2_i8)));
        assert_eq!(I128::try_from(&[u32::MAX - 1][..]), Ok(I128::from(-2_i8)));
        assert_eq!(I128::try_from(&[u64::MAX - 1][..]), Ok(I128::from(-2_i8)));

        assert_eq!(
            FixedBigInt::<0>::from_le_bytes(&[1]),
            Err(ConversionError::InputTooLarge)
        );
        assert_eq!(
            FixedBigInt::<0>::from_unsigned_le_u32(&[1]),
            Err(ConversionError::InputTooLarge)
        );
        assert_eq!(
            FixedBigInt::<0>::from_unsigned_le_u64(&[1]),
            Err(ConversionError::InputTooLarge)
        );
        assert_eq!(
            I128::zero().write_le_bytes(&mut [0_u8; 15]),
            Err(ConversionError::BufferTooSmall)
        );
        assert_eq!(
            I128::zero().write_le_u32(&mut [0_u32; 3]),
            Err(ConversionError::BufferTooSmall)
        );
        assert_eq!(
            I128::zero().write_le_u64(&mut [0_u64; 1]),
            Err(ConversionError::BufferTooSmall)
        );
    }

    #[test]
    fn negation_bitwise_not_and_shift_operator_forms_are_available() {
        let left = I128::from(0b1100_i8);
        let right = I128::from(0b1010_i8);

        macro_rules! assert_forms {
            ($operator:tt, $expected:expr) => {{
                assert_eq!(left $operator right, I128::from($expected));
                assert_eq!(left $operator &right, I128::from($expected));
                assert_eq!(&left $operator right, I128::from($expected));
                assert_eq!(&left $operator &right, I128::from($expected));
            }};
        }

        assert_forms!(&, 0b1000_i8);
        assert_forms!(|, 0b1110_i8);
        assert_forms!(^, 0b0110_i8);
        assert_eq!(-left, -&left);
        assert_eq!(!left, !&left);
        assert_eq!(left << 2, I128::from(48_i8));
        assert_eq!(&left << 2, I128::from(48_i8));
        assert_eq!(left >> 2, I128::from(3_i8));
        assert_eq!(&left >> 2, I128::from(3_i8));

        let mut assigned = I128::from(-1_i8);
        assigned &= &I128::from(0b1110_i8);
        assigned |= I128::from(1_i8);
        assigned ^= &I128::from(0b0101_i8);
        assigned <<= 2;
        assigned >>= 1;
        assert_eq!(assigned, I128::from(20_i8));
    }

    #[test]
    fn numeric_trait_specific_paths_are_covered() {
        let value = I128::from(-5_i8);
        assert_eq!(Pow::pow(value, 2_u32), I128::from(25_i8));
        assert_eq!(Pow::pow(value, &2_u32), I128::from(25_i8));
        assert_eq!(Pow::pow(&value, 2_u32), I128::from(25_i8));
        assert_eq!(Pow::pow(&value, &2_u32), I128::from(25_i8));
        assert_eq!(I128::from_i64(-9), Some(I128::from(-9_i8)));
        assert_eq!(I128::from_i128(i128::MIN), Some(I128::from(i128::MIN)));
        assert_eq!(I128::from_u64(u64::MAX), Some(I128::from(u64::MAX)));
        assert_eq!(I128::from_u128(u128::MAX), None);
        assert_eq!(I128::from(i128::MIN).to_i128(), Some(i128::MIN));
        assert_eq!(I128::from(-1_i8).to_u64(), None);
        assert_eq!(I128::from(u64::MAX).to_u64(), Some(u64::MAX));
        assert_eq!(I128::from(-1_i8).to_u128(), None);
    }

    #[test]
    #[should_panic(expected = "bit index is outside fixed width")]
    fn set_bit_rejects_out_of_range_index() {
        let _ = I128::zero().set_bit(128);
    }

    #[test]
    #[should_panic(expected = "bit index is outside fixed width")]
    fn clear_bit_rejects_out_of_range_index() {
        let _ = I128::zero().clear_bit(128);
    }

    #[test]
    #[should_panic(expected = "bit index is outside fixed width")]
    fn flip_bit_rejects_out_of_range_index() {
        let _ = I128::zero().flip_bit(128);
    }

    #[test]
    #[should_panic(expected = "attempted to negate with overflow")]
    fn negation_rejects_minimum_value() {
        let _ = -I128::min_value();
    }

    #[test]
    #[should_panic(expected = "attempted to shift left with overflow")]
    fn left_shift_rejects_width_or_larger() {
        let _ = I128::from(1_i8) << 128;
    }

    #[test]
    #[should_panic(expected = "attempted to shift right with overflow")]
    fn right_shift_rejects_width_or_larger() {
        let _ = I128::from(1_i8) >> 128;
    }

    #[test]
    #[should_panic(expected = "modulus must be positive")]
    fn modular_inverse_rejects_non_positive_modulus() {
        let _ = I128::from(1_i8).mod_inverse(&I128::zero());
    }

    #[test]
    #[should_panic(expected = "modulus must be positive")]
    fn modular_power_rejects_non_positive_modulus() {
        let _ = I128::from(1_i8).mod_pow(&I128::from(2_i8), &I128::from(-3_i8));
    }

    #[test]
    #[should_panic(expected = "base is not invertible for a negative exponent")]
    fn negative_modular_power_rejects_a_non_invertible_base() {
        let _ = I128::from(2_i8).mod_pow(&I128::from(-1_i8), &I128::from(4_i8));
    }
}
