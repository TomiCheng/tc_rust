//! Conversions from primitive signed integers.

use crate::{FixedBigInt, Limb, Word};

impl<const N: usize> FixedBigInt<N> {
    /// Creates a fixed-precision integer from an `i8`.
    ///
    /// Negative values are sign-extended across all limbs.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation when `N` is zero.
    #[inline]
    #[must_use]
    pub const fn from_i8(value: i8) -> Self {
        Self::from_signed_word(value as Word, value < 0)
    }

    /// Creates a fixed-precision integer from an `i16`.
    ///
    /// Negative values are sign-extended across all limbs.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation when `N` is zero.
    #[inline]
    #[must_use]
    pub const fn from_i16(value: i16) -> Self {
        Self::from_signed_word(value as Word, value < 0)
    }

    /// Creates a fixed-precision integer from an `i32`.
    ///
    /// Negative values are sign-extended across all limbs.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation when `N` is zero.
    #[inline]
    #[must_use]
    pub const fn from_i32(value: i32) -> Self {
        Self::from_signed_word(value as Word, value < 0)
    }

    /// Creates a fixed-precision integer from an `i64`.
    ///
    /// Negative values are sign-extended across the remaining high limbs.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation when `N` is too small to contain all
    /// 64 bits of the input type.
    #[inline]
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        const {
            assert!(
                N >= 64 / Word::BITS as usize,
                "number of limbs is too small for i64"
            );
        }

        let extension = if value < 0 { Limb(Word::MAX) } else { Limb(0) };
        let mut limbs = [extension; N];

        #[cfg(target_pointer_width = "64")]
        {
            limbs[0] = Limb(value as Word);
        }

        #[cfg(not(target_pointer_width = "64"))]
        {
            let bits = value as u64;
            limbs[0] = Limb(bits as Word);
            limbs[1] = Limb((bits >> 32) as Word);
        }

        Self { limbs }
    }

    /// Creates a fixed-precision integer from an `i128`.
    ///
    /// Negative values are sign-extended across the remaining high limbs.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation when `N` is too small to contain all
    /// 128 bits of the input type.
    #[inline]
    #[must_use]
    pub const fn from_i128(value: i128) -> Self {
        const {
            assert!(
                N >= 128 / Word::BITS as usize,
                "number of limbs is too small for i128"
            );
        }

        let extension = if value < 0 { Limb(Word::MAX) } else { Limb(0) };
        let mut limbs = [extension; N];
        let bits = value as u128;

        #[cfg(target_pointer_width = "64")]
        {
            limbs[0] = Limb(bits as Word);
            limbs[1] = Limb((bits >> 64) as Word);
        }

        #[cfg(not(target_pointer_width = "64"))]
        {
            limbs[0] = Limb(bits as Word);
            limbs[1] = Limb((bits >> 32) as Word);
            limbs[2] = Limb((bits >> 64) as Word);
            limbs[3] = Limb((bits >> 96) as Word);
        }

        Self { limbs }
    }

    const fn from_signed_word(value: Word, negative: bool) -> Self {
        const {
            assert!(N >= 1, "number of limbs is too small for signed integer");
        }

        let extension = if negative { Limb(Word::MAX) } else { Limb(0) };
        let mut limbs = [extension; N];
        limbs[0] = Limb(value);
        Self { limbs }
    }
}

macro_rules! impl_from_signed {
    ($($primitive:ty => $constructor:ident),* $(,)?) => {
        $(
            impl<const N: usize> From<$primitive> for FixedBigInt<N> {
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

#[cfg(test)]
mod tests {
    use crate::{I128, I1024, Limb, Word};

    const POSITIVE: I128 = I128::from_i64(0x1122_3344_5566_7788);
    const NEGATIVE: I128 = I128::from_i64(-2);

    #[test]
    fn smaller_primitive_constructors_are_const_and_sign_extend() {
        const FROM_I8: I128 = I128::from_i8(-2);
        const FROM_I16: I128 = I128::from_i16(-2);
        const FROM_I32: I128 = I128::from_i32(-2);

        assert_eq!(FROM_I8, I128::from_i128(-2));
        assert_eq!(FROM_I16, I128::from_i128(-2));
        assert_eq!(FROM_I32, I128::from_i128(-2));
    }

    #[test]
    fn from_traits_use_the_const_constructors() {
        assert_eq!(I128::from(-2_i8), I128::from_i8(-2));
        assert_eq!(I128::from(-2_i16), I128::from_i16(-2));
        assert_eq!(I128::from(-2_i32), I128::from_i32(-2));
        assert_eq!(I128::from(-2_i64), I128::from_i64(-2));
        assert_eq!(I128::from(-2_i128), I128::from_i128(-2));

        let into: I128 = (-2_i64).into();
        assert_eq!(into, I128::from_i64(-2));
    }

    #[test]
    fn from_i64_zero_extends_positive_values() {
        #[cfg(target_pointer_width = "64")]
        assert_eq!(POSITIVE.limbs, [Limb(0x1122_3344_5566_7788), Limb(0)]);

        #[cfg(not(target_pointer_width = "64"))]
        assert_eq!(
            POSITIVE.limbs,
            [Limb(0x5566_7788), Limb(0x1122_3344), Limb(0), Limb(0)]
        );
    }

    #[test]
    fn from_i64_sign_extends_negative_values() {
        #[cfg(target_pointer_width = "64")]
        assert_eq!(NEGATIVE.limbs, [Limb(Word::MAX - 1), Limb(Word::MAX)]);

        #[cfg(not(target_pointer_width = "64"))]
        assert_eq!(
            NEGATIVE.limbs,
            [
                Limb(Word::MAX - 1),
                Limb(Word::MAX),
                Limb(Word::MAX),
                Limb(Word::MAX),
            ]
        );
    }

    #[test]
    fn from_i128_stores_all_source_bits() {
        const VALUE: i128 = 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00;
        const RESULT: I128 = I128::from_i128(VALUE);

        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            RESULT.limbs,
            [Limb(0x99aa_bbcc_ddee_ff00), Limb(0x1122_3344_5566_7788)]
        );

        #[cfg(not(target_pointer_width = "64"))]
        assert_eq!(
            RESULT.limbs,
            [
                Limb(0xddee_ff00),
                Limb(0x99aa_bbcc),
                Limb(0x5566_7788),
                Limb(0x1122_3344),
            ]
        );
    }

    #[test]
    fn from_i128_sign_extends_into_larger_widths() {
        const VALUE: I1024 = I1024::from_i128(-2);

        assert_eq!(VALUE.limbs[0], Limb(Word::MAX - 1));
        assert!(VALUE.limbs[1..].iter().all(|limb| limb.0 == Word::MAX));
    }
}
