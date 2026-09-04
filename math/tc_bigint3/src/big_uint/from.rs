//! Conversions for [`BigUint`].

use alloc::vec::Vec;

use crate::traits::{FromPrimitive, ToPrimitive};
use crate::{BigUint, ConversionError, FixedBigUint, Limb};

macro_rules! impl_from_unsigned {
    ($($type:ty),* $(,)?) => {
        $(
            impl From<$type> for BigUint {
                fn from(value: $type) -> Self {
                    Self::from_le_bytes(&value.to_le_bytes())
                }
            }
        )*
    };
}

impl_from_unsigned!(u8, u16, u32, u64, u128, usize);

impl From<&[u8]> for BigUint {
    fn from(value: &[u8]) -> Self {
        Self::from_le_bytes(value)
    }
}

impl From<&[u32]> for BigUint {
    fn from(value: &[u32]) -> Self {
        Self::from_le_u32(value)
    }
}

impl From<&[u64]> for BigUint {
    fn from(value: &[u64]) -> Self {
        Self::from_le_u64(value)
    }
}

impl<const N: usize> From<FixedBigUint<N>> for BigUint {
    fn from(value: FixedBigUint<N>) -> Self {
        Self::from_limbs(Vec::from(*value.as_limbs()))
    }
}

impl<const N: usize> TryFrom<&BigUint> for FixedBigUint<N> {
    type Error = ConversionError;

    fn try_from(value: &BigUint) -> Result<Self, Self::Error> {
        if value.limbs.len() > N {
            return Err(ConversionError::InputTooLarge);
        }
        let mut limbs = [Limb(0); N];
        limbs[..value.limbs.len()].copy_from_slice(&value.limbs);
        Ok(Self::from_limbs(limbs))
    }
}

impl FromPrimitive for BigUint {
    fn from_i64(value: i64) -> Option<Self> {
        u64::try_from(value).ok().map(Self::from)
    }

    fn from_i128(value: i128) -> Option<Self> {
        u128::try_from(value).ok().map(Self::from)
    }

    fn from_u64(value: u64) -> Option<Self> {
        Some(Self::from(value))
    }

    fn from_u128(value: u128) -> Option<Self> {
        Some(Self::from(value))
    }
}

impl ToPrimitive for BigUint {
    fn to_i64(&self) -> Option<i64> {
        self.to_u64().and_then(|value| i64::try_from(value).ok())
    }

    fn to_i128(&self) -> Option<i128> {
        self.to_u128().and_then(|value| i128::try_from(value).ok())
    }

    fn to_u64(&self) -> Option<u64> {
        let words = self.to_le_u64();
        (words.len() == 1).then_some(words[0])
    }

    fn to_u128(&self) -> Option<u128> {
        let words = self.to_le_u64();
        if words.len() > 2 {
            None
        } else {
            Some(words[0] as u128 | (words.get(1).copied().unwrap_or(0) as u128) << 64)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::traits::{FromPrimitive, ToPrimitive};
    use crate::{BigUint, FixedBigUint};

    #[test]
    fn every_primitive_from_impl_preserves_the_value() {
        assert_eq!(BigUint::from(1_u8).to_u128(), Some(1));
        assert_eq!(BigUint::from(2_u16).to_u128(), Some(2));
        assert_eq!(BigUint::from(3_u32).to_u128(), Some(3));
        assert_eq!(BigUint::from(4_u64).to_u128(), Some(4));
        assert_eq!(BigUint::from(5_u128).to_u128(), Some(5));
        assert_eq!(BigUint::from(6_usize).to_u128(), Some(6));
    }

    #[test]
    fn slice_fixed_and_numeric_trait_conversions_are_covered() {
        assert_eq!(BigUint::from(&[7_u8][..]), BigUint::from(7_u8));
        assert_eq!(BigUint::from(&[8_u32][..]), BigUint::from(8_u8));
        assert_eq!(BigUint::from(&[9_u64][..]), BigUint::from(9_u8));

        let fixed = FixedBigUint::<2>::from(10_u8);
        assert_eq!(BigUint::from(fixed), BigUint::from(10_u8));
        assert_eq!(
            FixedBigUint::<2>::try_from(&BigUint::from(11_u8)),
            Ok(FixedBigUint::from(11_u8))
        );

        assert_eq!(BigUint::from_i64(12), Some(BigUint::from(12_u8)));
        assert_eq!(BigUint::from_i128(13), Some(BigUint::from(13_u8)));
        assert_eq!(BigUint::from_u64(14), Some(BigUint::from(14_u8)));
        assert_eq!(BigUint::from_u128(15), Some(BigUint::from(15_u8)));
        assert_eq!(BigUint::from(16_u8).to_i64(), Some(16));
        assert_eq!(BigUint::from(17_u8).to_i128(), Some(17));
        assert_eq!(BigUint::from(18_u8).to_u64(), Some(18));
        assert_eq!(BigUint::from(19_u8).to_u128(), Some(19));
    }
}
