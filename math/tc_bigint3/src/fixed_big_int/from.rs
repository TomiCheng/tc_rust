//! Conversions for [`FixedBigInt`].

use crate::traits::{FromPrimitive, ToPrimitive};
use crate::{ConversionError, FixedBigInt, FixedBigUint};

macro_rules! impl_from_signed {
    ($($type:ty),* $(,)?) => {
        $(
            impl<const N: usize> From<$type> for FixedBigInt<N> {
                fn from(value: $type) -> Self {
                    Self::from_le_bytes(&value.to_le_bytes())
                        .expect("primitive value does not fit in FixedBigInt")
                }
            }
        )*
    };
}

macro_rules! impl_from_unsigned {
    ($($type:ty),* $(,)?) => {
        $(
            impl<const N: usize> From<$type> for FixedBigInt<N> {
                fn from(value: $type) -> Self {
                    Self::from_unsigned_le_bytes(&value.to_le_bytes())
                        .expect("primitive value does not fit in FixedBigInt")
                }
            }
        )*
    };
}

impl_from_signed!(i8, i16, i32, i64, i128, isize);
impl_from_unsigned!(u8, u16, u32, u64, u128, usize);

impl<const N: usize> TryFrom<&[u8]> for FixedBigInt<N> {
    type Error = ConversionError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_le_bytes(value)
    }
}

impl<const N: usize> TryFrom<&[u32]> for FixedBigInt<N> {
    type Error = ConversionError;

    fn try_from(value: &[u32]) -> Result<Self, Self::Error> {
        Self::from_le_u32(value)
    }
}

impl<const N: usize> TryFrom<&[u64]> for FixedBigInt<N> {
    type Error = ConversionError;

    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        Self::from_le_u64(value)
    }
}

impl<const N: usize> FromPrimitive for FixedBigInt<N> {
    fn from_i64(value: i64) -> Option<Self> {
        Self::from_le_bytes(&value.to_le_bytes()).ok()
    }

    fn from_i128(value: i128) -> Option<Self> {
        Self::from_le_bytes(&value.to_le_bytes()).ok()
    }

    fn from_u64(value: u64) -> Option<Self> {
        Self::from_unsigned_le_bytes(&value.to_le_bytes()).ok()
    }

    fn from_u128(value: u128) -> Option<Self> {
        Self::from_unsigned_le_bytes(&value.to_le_bytes()).ok()
    }
}

impl<const N: usize> ToPrimitive for FixedBigInt<N> {
    fn to_i64(&self) -> Option<i64> {
        self.to_i128().and_then(|value| i64::try_from(value).ok())
    }

    fn to_i128(&self) -> Option<i128> {
        self.checked_i128()
    }

    fn to_u64(&self) -> Option<u64> {
        self.to_u128().and_then(|value| u64::try_from(value).ok())
    }

    fn to_u128(&self) -> Option<u128> {
        if self.is_negative() {
            None
        } else {
            FixedBigUint::from_limbs(self.limbs).to_u128()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::FixedBigInt;
    use crate::traits::{FromPrimitive, ToPrimitive};

    type I = FixedBigInt<2>;

    #[test]
    fn every_primitive_and_slice_conversion_is_covered() {
        assert_eq!(I::from(-1_i8).to_i128(), Some(-1));
        assert_eq!(I::from(-2_i16).to_i128(), Some(-2));
        assert_eq!(I::from(-3_i32).to_i128(), Some(-3));
        assert_eq!(I::from(-4_i64).to_i128(), Some(-4));
        assert_eq!(I::from(-5_i128).to_i128(), Some(-5));
        assert_eq!(I::from(-6_isize).to_i128(), Some(-6));
        assert_eq!(I::from(7_u8).to_u128(), Some(7));
        assert_eq!(I::from(8_u16).to_u128(), Some(8));
        assert_eq!(I::from(9_u32).to_u128(), Some(9));
        assert_eq!(I::from(10_u64).to_u128(), Some(10));
        assert_eq!(I::from(11_u128).to_u128(), Some(11));
        assert_eq!(I::from(12_usize).to_u128(), Some(12));
        assert_eq!(I::try_from(&[0xff_u8][..]), Ok(I::from(-1_i8)));
        assert_eq!(I::try_from(&[u32::MAX][..]), Ok(I::from(-1_i8)));
        assert_eq!(I::try_from(&[u64::MAX][..]), Ok(I::from(-1_i8)));
    }

    #[test]
    fn primitive_traits_cover_signed_unsigned_and_narrowing_results() {
        assert_eq!(I::from_i64(-13), Some(I::from(-13_i8)));
        assert_eq!(I::from_i128(-14), Some(I::from(-14_i8)));
        assert_eq!(I::from_u64(15), Some(I::from(15_u8)));
        assert_eq!(I::from_u128(16), Some(I::from(16_u8)));
        assert_eq!(I::from(-17_i8).to_i64(), Some(-17));
        assert_eq!(I::from(-18_i8).to_i128(), Some(-18));
        assert_eq!(I::from(19_u8).to_u64(), Some(19));
        assert_eq!(I::from(20_u8).to_u128(), Some(20));
    }
}
