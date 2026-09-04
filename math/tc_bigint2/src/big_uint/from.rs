//! Conversions into arbitrary-precision unsigned integers.

use alloc::vec::Vec;

use crate::{BigUint, FixedBigUint, Limb, Word};

impl BigUint {
    /// Creates an arbitrary-precision integer from a `u8`.
    #[inline]
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        Self::from_word(value as Word)
    }

    /// Creates an arbitrary-precision integer from a `u16`.
    #[inline]
    #[must_use]
    pub fn from_u16(value: u16) -> Self {
        Self::from_word(value as Word)
    }

    /// Creates an arbitrary-precision integer from a `u32`.
    #[inline]
    #[must_use]
    pub fn from_u32(value: u32) -> Self {
        Self::from_word(value as Word)
    }

    /// Creates an arbitrary-precision integer from a `u64`.
    #[inline]
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        #[cfg(target_pointer_width = "64")]
        let limbs = Vec::from([Limb(value as Word)]);

        #[cfg(not(target_pointer_width = "64"))]
        let limbs = Vec::from([Limb(value as Word), Limb((value >> 32) as Word)]);

        Self::from_limbs(limbs)
    }

    /// Creates an arbitrary-precision integer from a `u128`.
    #[inline]
    #[must_use]
    pub fn from_u128(value: u128) -> Self {
        #[cfg(target_pointer_width = "64")]
        let limbs = Vec::from([Limb(value as Word), Limb((value >> 64) as Word)]);

        #[cfg(not(target_pointer_width = "64"))]
        let limbs = Vec::from([
            Limb(value as Word),
            Limb((value >> 32) as Word),
            Limb((value >> 64) as Word),
            Limb((value >> 96) as Word),
        ]);

        Self::from_limbs(limbs)
    }

    fn from_word(value: Word) -> Self {
        Self::from_limbs(Vec::from([Limb(value)]))
    }
}

macro_rules! impl_from_unsigned {
    ($($primitive:ty => $constructor:ident),* $(,)?) => {
        $(
            impl From<$primitive> for BigUint {
                #[inline]
                fn from(value: $primitive) -> Self {
                    Self::$constructor(value)
                }
            }
        )*
    };
}

impl_from_unsigned! {
    u8 => from_u8,
    u16 => from_u16,
    u32 => from_u32,
    u64 => from_u64,
    u128 => from_u128,
}

impl<const N: usize> From<FixedBigUint<N>> for BigUint {
    fn from(value: FixedBigUint<N>) -> Self {
        Self::from_limbs(value.into_limbs().into())
    }
}

#[cfg(test)]
mod tests {
    use crate::{BigUint, Limb, U128};

    #[test]
    fn primitive_constructors_match_fixed_conversions() {
        assert_eq!(BigUint::from_u8(2), BigUint::from(U128::from_u8(2)));
        assert_eq!(BigUint::from_u16(2), BigUint::from(U128::from_u16(2)));
        assert_eq!(BigUint::from_u32(2), BigUint::from(U128::from_u32(2)));
        assert_eq!(BigUint::from_u64(2), BigUint::from(U128::from_u64(2)));
        assert_eq!(BigUint::from_u128(2), BigUint::from(U128::from_u128(2)));
    }

    #[test]
    fn primitive_zero_uses_an_empty_limb_vector() {
        assert!(BigUint::from_u8(0).limbs.is_empty());
        assert!(BigUint::from_u128(0).limbs.is_empty());
    }

    #[test]
    fn primitive_from_traits_use_the_constructors() {
        assert_eq!(BigUint::from(2_u8), BigUint::from_u8(2));
        assert_eq!(BigUint::from(2_u16), BigUint::from_u16(2));
        assert_eq!(BigUint::from(2_u32), BigUint::from_u32(2));
        assert_eq!(BigUint::from(2_u64), BigUint::from_u64(2));
        assert_eq!(BigUint::from(2_u128), BigUint::from_u128(2));

        let into: BigUint = 2_u64.into();
        assert_eq!(into, BigUint::from_u64(2));
    }

    #[test]
    fn from_u128_keeps_all_source_bits() {
        let value = BigUint::from_u128(u128::MAX);

        assert!(value.limbs.iter().all(|limb| limb.0 == crate::Word::MAX));
        assert_eq!(value.limbs.len() as u32 * crate::Word::BITS, 128);
    }

    #[test]
    fn converts_fixed_uint_and_removes_high_zero_limbs() {
        let value = U128::from_u64(0x1122_3344_5566_7788);
        let value = BigUint::from(value);

        #[cfg(target_pointer_width = "64")]
        assert_eq!(value.limbs, [Limb(0x1122_3344_5566_7788)]);

        #[cfg(not(target_pointer_width = "64"))]
        assert_eq!(value.limbs, [Limb(0x5566_7788), Limb(0x1122_3344)]);
    }

    #[test]
    fn converts_zero_to_an_empty_magnitude() {
        let value = BigUint::from(U128::from_u64(0));

        assert!(value.limbs.is_empty());
    }
}
