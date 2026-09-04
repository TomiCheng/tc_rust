//! Conversions for [`FixedBigUint`].

use core::str::FromStr;

use crate::traits::{FromPrimitive, ToPrimitive};
use crate::{ConversionError, FixedBigInt, FixedBigUint, Limb};

impl<const N: usize> FromStr for FixedBigUint<N> {
    type Err = crate::ParseBigIntError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_str_radix(value, 10)
    }
}

macro_rules! impl_from_unsigned {
    ($($type:ty),* $(,)?) => {
        $(
            impl<const N: usize> From<$type> for FixedBigUint<N> {
                fn from(value: $type) -> Self {
                    Self::from_le_bytes(&value.to_le_bytes())
                        .expect("primitive value does not fit in FixedBigUint")
                }
            }
        )*
    };
}

impl_from_unsigned!(u8, u16, u32, u64, u128, usize);

impl<const N: usize> TryFrom<FixedBigInt<N>> for FixedBigUint<N> {
    type Error = ConversionError;

    fn try_from(value: FixedBigInt<N>) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl<const N: usize> TryFrom<&FixedBigInt<N>> for FixedBigUint<N> {
    type Error = ConversionError;

    fn try_from(value: &FixedBigInt<N>) -> Result<Self, Self::Error> {
        if value.is_negative() {
            return Err(ConversionError::NegativeValue);
        }
        Ok(Self::from_limbs(*value.as_limbs()))
    }
}

impl<const SOURCE: usize, const DESTINATION: usize> TryFrom<&FixedBigUint<SOURCE>>
    for FixedBigUint<DESTINATION>
{
    type Error = ConversionError;

    fn try_from(value: &FixedBigUint<SOURCE>) -> Result<Self, Self::Error> {
        if value.as_limbs()[DESTINATION.min(SOURCE)..]
            .iter()
            .any(|limb| limb.0 != 0)
        {
            return Err(ConversionError::InputTooLarge);
        }
        let mut limbs = [Limb(0); DESTINATION];
        let copy_len = SOURCE.min(DESTINATION);
        limbs[..copy_len].copy_from_slice(&value.as_limbs()[..copy_len]);
        Ok(Self::from_limbs(limbs))
    }
}

impl<const N: usize> TryFrom<&[u8]> for FixedBigUint<N> {
    type Error = ConversionError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_le_bytes(value)
    }
}

impl<const N: usize> TryFrom<&[u32]> for FixedBigUint<N> {
    type Error = ConversionError;

    fn try_from(value: &[u32]) -> Result<Self, Self::Error> {
        Self::from_le_u32(value)
    }
}

impl<const N: usize> TryFrom<&[u64]> for FixedBigUint<N> {
    type Error = ConversionError;

    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        Self::from_le_u64(value)
    }
}

impl<const N: usize> FromPrimitive for FixedBigUint<N> {
    fn from_i64(value: i64) -> Option<Self> {
        u64::try_from(value).ok().and_then(Self::from_u64)
    }

    fn from_i128(value: i128) -> Option<Self> {
        u128::try_from(value).ok().and_then(Self::from_u128)
    }

    fn from_u64(value: u64) -> Option<Self> {
        Self::from_le_bytes(&value.to_le_bytes()).ok()
    }

    fn from_u128(value: u128) -> Option<Self> {
        Self::from_le_bytes(&value.to_le_bytes()).ok()
    }
}

impl<const N: usize> ToPrimitive for FixedBigUint<N> {
    fn to_i64(&self) -> Option<i64> {
        self.to_u64().and_then(|value| i64::try_from(value).ok())
    }

    fn to_i128(&self) -> Option<i128> {
        self.to_u128().and_then(|value| i128::try_from(value).ok())
    }

    fn to_u64(&self) -> Option<u64> {
        self.checked_u128()
            .and_then(|value| u64::try_from(value).ok())
    }

    fn to_u128(&self) -> Option<u128> {
        self.checked_u128()
    }
}

#[cfg(test)]
mod tests {
    use crate::{ConversionError, FixedBigInt, FixedBigUint, Word};
    use crate::traits::{FromPrimitive, ToPrimitive};

    type U = FixedBigUint<2>;

    #[test]
    fn every_primitive_and_slice_conversion_is_covered() {
        assert_eq!(U::from(1_u8).to_u128(), Some(1));
        assert_eq!(U::from(2_u16).to_u128(), Some(2));
        assert_eq!(U::from(3_u32).to_u128(), Some(3));
        assert_eq!(U::from(4_u64).to_u128(), Some(4));
        assert_eq!(U::from(5_u128).to_u128(), Some(5));
        assert_eq!(U::from(6_usize).to_u128(), Some(6));
        assert_eq!(U::try_from(&[7_u8][..]), Ok(U::from(7_u8)));
        assert_eq!(U::try_from(&[8_u32][..]), Ok(U::from(8_u8)));
        assert_eq!(U::try_from(&[9_u64][..]), Ok(U::from(9_u8)));
    }

    #[test]
    fn primitive_traits_cover_signed_unsigned_and_narrowing_results() {
        assert_eq!(U::from_i64(-1), None);
        assert_eq!(U::from_i128(-1), None);
        assert_eq!(U::from_u64(10), Some(U::from(10_u8)));
        assert_eq!(U::from_u128(11), Some(U::from(11_u8)));
        assert_eq!(U::from(12_u8).to_i64(), Some(12));
        assert_eq!(U::from(13_u8).to_i128(), Some(13));
        assert_eq!(U::from(14_u8).to_u64(), Some(14));
        assert_eq!(U::from(15_u8).to_u128(), Some(15));
    }

    #[test]
    fn signed_and_different_width_conversions_are_checked() {
        assert_eq!(
            FixedBigUint::<2>::try_from(FixedBigInt::<2>::from(42_i8)),
            Ok(FixedBigUint::from(42_u8))
        );
        assert_eq!(
            FixedBigUint::<2>::try_from(&FixedBigInt::<2>::from(-1_i8)),
            Err(ConversionError::NegativeValue)
        );

        let narrow = FixedBigUint::<1>::from(7_u8);
        assert_eq!(
            FixedBigUint::<3>::try_from(&narrow),
            Ok(FixedBigUint::from(7_u8))
        );
        let wide = FixedBigUint::<2>::from(1_u8).set_bit(Word::BITS as usize);
        assert_eq!(
            FixedBigUint::<1>::try_from(&wide),
            Err(ConversionError::InputTooLarge)
        );
    }
}
