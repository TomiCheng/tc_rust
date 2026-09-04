//! Conversions for [`BigInt`].

use alloc::vec::Vec;
use core::str::FromStr;

use crate::arithmetic;
use crate::encoding;
use crate::traits::{FromPrimitive, ToPrimitive};
use crate::{BigInt, ConversionError, FixedBigInt, Limb, Word};

macro_rules! impl_from_signed {
    ($($type:ty),* $(,)?) => {
        $(
            impl From<$type> for BigInt {
                fn from(value: $type) -> Self {
                    Self::from_le_bytes(&value.to_le_bytes())
                }
            }
        )*
    };
}

macro_rules! impl_from_unsigned {
    ($($type:ty),* $(,)?) => {
        $(
            impl From<$type> for BigInt {
                fn from(value: $type) -> Self {
                    Self::from_unsigned_le_bytes(&value.to_le_bytes())
                }
            }
        )*
    };
}

impl_from_signed!(i8, i16, i32, i64, i128, isize);
impl_from_unsigned!(u8, u16, u32, u64, u128, usize);

impl FromStr for BigInt {
    type Err = crate::ParseBigIntError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_str_radix(value, 10)
    }
}

impl From<&[u8]> for BigInt {
    fn from(value: &[u8]) -> Self {
        Self::from_le_bytes(value)
    }
}

impl From<&[u32]> for BigInt {
    fn from(value: &[u32]) -> Self {
        Self::from_le_u32(value)
    }
}

impl From<&[u64]> for BigInt {
    fn from(value: &[u64]) -> Self {
        Self::from_le_u64(value)
    }
}

impl<const N: usize> From<FixedBigInt<N>> for BigInt {
    fn from(value: FixedBigInt<N>) -> Self {
        Self::from_limbs(Vec::from(*value.as_limbs()))
    }
}

impl<const N: usize> TryFrom<&BigInt> for FixedBigInt<N> {
    type Error = ConversionError;

    fn try_from(value: &BigInt) -> Result<Self, Self::Error> {
        let negative = value.is_negative();
        let extension = if negative { Limb(Word::MAX) } else { Limb(0) };
        if value.limbs.len() > N && value.limbs[N..].iter().any(|word| *word != extension) {
            return Err(ConversionError::InputTooLarge);
        }
        let mut limbs = [extension; N];
        let copy_len = value.limbs.len().min(N);
        limbs[..copy_len].copy_from_slice(&value.limbs[..copy_len]);
        if N == 0 {
            return value
                .is_zero()
                .then_some(FixedBigInt::from_limbs(limbs))
                .ok_or(ConversionError::InputTooLarge);
        }
        if arithmetic::fixed_is_negative(&limbs) != negative && !value.is_zero() {
            return Err(ConversionError::InputTooLarge);
        }
        Ok(FixedBigInt::from_limbs(limbs))
    }
}

impl FromPrimitive for BigInt {
    fn from_i64(value: i64) -> Option<Self> {
        Some(Self::from(value))
    }

    fn from_i128(value: i128) -> Option<Self> {
        Some(Self::from(value))
    }

    fn from_u64(value: u64) -> Option<Self> {
        Some(Self::from(value))
    }

    fn from_u128(value: u128) -> Option<Self> {
        Some(Self::from(value))
    }
}

impl ToPrimitive for BigInt {
    fn to_i64(&self) -> Option<i64> {
        signed_to_i128(self).and_then(|value| i64::try_from(value).ok())
    }

    fn to_i128(&self) -> Option<i128> {
        signed_to_i128(self)
    }

    fn to_u64(&self) -> Option<u64> {
        self.to_u128().and_then(|value| u64::try_from(value).ok())
    }

    fn to_u128(&self) -> Option<u128> {
        let (negative, magnitude) = self.sign_magnitude();
        if negative {
            return None;
        }
        magnitude_to_u128(&magnitude)
    }
}

fn signed_to_i128(value: &BigInt) -> Option<i128> {
    let (negative, magnitude) = value.sign_magnitude();
    let magnitude = magnitude_to_u128(&magnitude)?;
    if negative {
        if magnitude == 1_u128 << 127 {
            Some(i128::MIN)
        } else {
            i128::try_from(magnitude).ok().map(|value| -value)
        }
    } else {
        i128::try_from(magnitude).ok()
    }
}

fn magnitude_to_u128(magnitude: &[Limb]) -> Option<u128> {
    if arithmetic::bit_len(magnitude) > 128 {
        return None;
    }
    let words = encoding::unsigned_to_le_u64(magnitude);
    Some(words[0] as u128 | (words.get(1).copied().unwrap_or(0) as u128) << 64)
}

#[cfg(test)]
mod tests {
    use crate::traits::{FromPrimitive, ToPrimitive};
    use crate::{BigInt, FixedBigInt};

    #[test]
    fn every_signed_and_unsigned_primitive_from_impl_preserves_the_value() {
        assert_eq!(BigInt::from(-1_i8).to_i128(), Some(-1));
        assert_eq!(BigInt::from(-2_i16).to_i128(), Some(-2));
        assert_eq!(BigInt::from(-3_i32).to_i128(), Some(-3));
        assert_eq!(BigInt::from(-4_i64).to_i128(), Some(-4));
        assert_eq!(BigInt::from(-5_i128).to_i128(), Some(-5));
        assert_eq!(BigInt::from(-6_isize).to_i128(), Some(-6));
        assert_eq!(BigInt::from(7_u8).to_u128(), Some(7));
        assert_eq!(BigInt::from(8_u16).to_u128(), Some(8));
        assert_eq!(BigInt::from(9_u32).to_u128(), Some(9));
        assert_eq!(BigInt::from(10_u64).to_u128(), Some(10));
        assert_eq!(BigInt::from(11_u128).to_u128(), Some(11));
        assert_eq!(BigInt::from(12_usize).to_u128(), Some(12));
    }

    #[test]
    fn decimal_strings_parse_through_the_standard_trait() {
        assert_eq!(
            "-123456789".parse::<BigInt>(),
            Ok(BigInt::from(-123_456_789_i64))
        );
        assert!("1.5".parse::<BigInt>().is_err());
    }

    #[test]
    fn slice_fixed_and_numeric_trait_conversions_are_covered() {
        assert_eq!(BigInt::from(&[0xff_u8][..]), BigInt::from(-1_i8));
        assert_eq!(BigInt::from(&[u32::MAX][..]), BigInt::from(-1_i8));
        assert_eq!(BigInt::from(&[u64::MAX][..]), BigInt::from(-1_i8));

        let fixed = FixedBigInt::<2>::from(-13_i8);
        assert_eq!(BigInt::from(fixed), BigInt::from(-13_i8));
        assert_eq!(
            FixedBigInt::<2>::try_from(&BigInt::from(-14_i8)),
            Ok(FixedBigInt::from(-14_i8))
        );

        assert_eq!(BigInt::from_i64(-15), Some(BigInt::from(-15_i8)));
        assert_eq!(BigInt::from_i128(-16), Some(BigInt::from(-16_i8)));
        assert_eq!(BigInt::from_u64(17), Some(BigInt::from(17_u8)));
        assert_eq!(BigInt::from_u128(18), Some(BigInt::from(18_u8)));
        assert_eq!(BigInt::from(-19_i8).to_i64(), Some(-19));
        assert_eq!(BigInt::from(-20_i8).to_i128(), Some(-20));
        assert_eq!(BigInt::from(21_u8).to_u64(), Some(21));
        assert_eq!(BigInt::from(22_u8).to_u128(), Some(22));
    }
}
