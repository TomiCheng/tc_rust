//! Conversions into arbitrary-precision signed integers.

use alloc::vec::Vec;

use crate::{BigInt, FixedBigInt, Limb, Word};

impl BigInt {
    /// Creates an arbitrary-precision integer from an `i8`.
    #[inline]
    #[must_use]
    pub fn from_i8(value: i8) -> Self {
        Self::from_signed_word(value as Word)
    }

    /// Creates an arbitrary-precision integer from an `i16`.
    #[inline]
    #[must_use]
    pub fn from_i16(value: i16) -> Self {
        Self::from_signed_word(value as Word)
    }

    /// Creates an arbitrary-precision integer from an `i32`.
    #[inline]
    #[must_use]
    pub fn from_i32(value: i32) -> Self {
        Self::from_signed_word(value as Word)
    }

    /// Creates an arbitrary-precision integer from an `i64`.
    #[inline]
    #[must_use]
    pub fn from_i64(value: i64) -> Self {
        let bits = value as u64;

        #[cfg(target_pointer_width = "64")]
        let limbs = Vec::from([Limb(bits as Word)]);

        #[cfg(not(target_pointer_width = "64"))]
        let limbs = Vec::from([Limb(bits as Word), Limb((bits >> 32) as Word)]);

        Self::from_limbs(limbs)
    }

    /// Creates an arbitrary-precision integer from an `i128`.
    #[inline]
    #[must_use]
    pub fn from_i128(value: i128) -> Self {
        let bits = value as u128;

        #[cfg(target_pointer_width = "64")]
        let limbs = Vec::from([Limb(bits as Word), Limb((bits >> 64) as Word)]);

        #[cfg(not(target_pointer_width = "64"))]
        let limbs = Vec::from([
            Limb(bits as Word),
            Limb((bits >> 32) as Word),
            Limb((bits >> 64) as Word),
            Limb((bits >> 96) as Word),
        ]);

        Self::from_limbs(limbs)
    }

    fn from_signed_word(value: Word) -> Self {
        Self::from_limbs(Vec::from([Limb(value)]))
    }
}

macro_rules! impl_from_signed {
    ($($primitive:ty => $constructor:ident),* $(,)?) => {
        $(
            impl From<$primitive> for BigInt {
                #[inline]
                fn from(value: $primitive) -> Self {
                    Self::$constructor(value)
                }
            }
        )*
    };
}

impl_from_signed! {
    i8 => from_i8,
    i16 => from_i16,
    i32 => from_i32,
    i64 => from_i64,
    i128 => from_i128,
}

impl<const N: usize> From<FixedBigInt<N>> for BigInt {
    fn from(value: FixedBigInt<N>) -> Self {
        Self::from_limbs(Vec::from(value.into_limbs()))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use crate::{BigInt, I128, Limb, Word};

    #[test]
    fn primitive_constructors_match_fixed_conversions() {
        assert_eq!(BigInt::from_i8(-2), BigInt::from(I128::from_i8(-2)));
        assert_eq!(BigInt::from_i16(-2), BigInt::from(I128::from_i16(-2)));
        assert_eq!(BigInt::from_i32(-2), BigInt::from(I128::from_i32(-2)));
        assert_eq!(BigInt::from_i64(-2), BigInt::from(I128::from_i64(-2)));
        assert_eq!(BigInt::from_i128(-2), BigInt::from(I128::from_i128(-2)));
    }

    #[test]
    fn primitive_zero_uses_an_empty_limb_vector() {
        assert!(BigInt::from_i8(0).limbs.is_empty());
        assert!(BigInt::from_i128(0).limbs.is_empty());
    }

    #[test]
    fn primitive_from_traits_use_the_constructors() {
        assert_eq!(BigInt::from(-2_i8), BigInt::from_i8(-2));
        assert_eq!(BigInt::from(-2_i16), BigInt::from_i16(-2));
        assert_eq!(BigInt::from(-2_i32), BigInt::from_i32(-2));
        assert_eq!(BigInt::from(-2_i64), BigInt::from_i64(-2));
        assert_eq!(BigInt::from(-2_i128), BigInt::from_i128(-2));

        let into: BigInt = (-2_i64).into();
        assert_eq!(into, BigInt::from_i64(-2));
    }

    #[test]
    fn from_i128_preserves_the_sign_bit() {
        let positive = BigInt::from_i128(i128::MAX);
        let negative = BigInt::from_i128(i128::MIN);

        assert_eq!(positive.limbs.last(), Some(&Limb(Word::MAX >> 1)));
        assert_eq!(negative.limbs.last(), Some(&Limb(1 << (Word::BITS - 1))));
    }

    #[test]
    fn converts_positive_fixed_int() {
        let value = BigInt::from(I128::from_i64(0x1122_3344_5566_7788));

        #[cfg(target_pointer_width = "64")]
        assert_eq!(value.limbs, [Limb(0x1122_3344_5566_7788)]);

        #[cfg(not(target_pointer_width = "64"))]
        assert_eq!(value.limbs, [Limb(0x5566_7788), Limb(0x1122_3344)]);
    }

    #[test]
    fn converts_negative_fixed_int() {
        let value = BigInt::from(I128::from_i64(i64::MIN));

        #[cfg(target_pointer_width = "64")]
        assert_eq!(value.limbs, [Limb(1 << 63)]);

        #[cfg(not(target_pointer_width = "64"))]
        assert_eq!(value.limbs, [Limb(0), Limb(1 << 31)]);
    }

    #[test]
    fn converts_fixed_zero_without_negative_zero() {
        let value = BigInt::from(I128::from_i64(0));

        assert!(value.limbs.is_empty());
    }

    #[test]
    fn preserves_required_positive_sign_limb() {
        let value = BigInt::from_limbs(vec![Limb(Word::MAX), Limb(0)]);

        assert_eq!(value.limbs, [Limb(Word::MAX), Limb(0)]);
    }

    #[test]
    fn preserves_required_negative_sign_limb() {
        let value = BigInt::from_limbs(vec![Limb(0), Limb(Word::MAX)]);

        assert_eq!(value.limbs, [Limb(0), Limb(Word::MAX)]);
    }
}
