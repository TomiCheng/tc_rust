//! Conversions from primitive unsigned integers.

use crate::{FixedBigUint, Limb, Word};

impl<const N: usize> FixedBigUint<N> {
    /// Creates a fixed-precision integer from a `u8`.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation when `N` is zero.
    #[inline]
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        const {
            assert!(N >= 1, "number of limbs is too small for u8");
        }

        let mut limbs = [Limb(0); N];
        limbs[0] = Limb(value as Word);
        Self { limbs }
    }

    /// Creates a fixed-precision integer from a `u16`.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation when `N` is zero.
    #[inline]
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        const {
            assert!(N >= 1, "number of limbs is too small for u16");
        }

        let mut limbs = [Limb(0); N];
        limbs[0] = Limb(value as Word);
        Self { limbs }
    }

    /// Creates a fixed-precision integer from a `u32`.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation when `N` is zero.
    #[inline]
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        const {
            assert!(N >= 1, "number of limbs is too small for u32");
        }

        let mut limbs = [Limb(0); N];
        limbs[0] = Limb(value as Word);
        Self { limbs }
    }

    /// Creates a fixed-precision integer from a `u64`.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation when `N` is too small to contain all
    /// 64 bits of the input type.
    #[inline]
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        const {
            assert!(
                N >= 64 / Word::BITS as usize,
                "number of limbs is too small for u64"
            );
        }

        let mut limbs = [Limb(0); N];

        #[cfg(target_pointer_width = "64")]
        {
            limbs[0] = Limb(value);
        }

        #[cfg(not(target_pointer_width = "64"))]
        {
            limbs[0] = Limb(value as Word);
            limbs[1] = Limb((value >> 32) as Word);
        }

        Self { limbs }
    }

    /// Creates a fixed-precision integer from a `u128`.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation when `N` is too small to contain all
    /// 128 bits of the input type.
    #[inline]
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        const {
            assert!(
                N >= 128 / Word::BITS as usize,
                "number of limbs is too small for u128"
            );
        }

        let mut limbs = [Limb(0); N];

        #[cfg(target_pointer_width = "64")]
        {
            limbs[0] = Limb(value as Word);
            limbs[1] = Limb((value >> 64) as Word);
        }

        #[cfg(not(target_pointer_width = "64"))]
        {
            limbs[0] = Limb(value as Word);
            limbs[1] = Limb((value >> 32) as Word);
            limbs[2] = Limb((value >> 64) as Word);
            limbs[3] = Limb((value >> 96) as Word);
        }

        Self { limbs }
    }
}

macro_rules! impl_from_unsigned {
    ($($primitive:ty => $constructor:ident),* $(,)?) => {
        $(
            impl<const N: usize> From<$primitive> for FixedBigUint<N> {
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

#[cfg(test)]
mod tests {
    use crate::{FixedBigUint, Limb, U128};

    const VALUE: u64 = 0x1122_3344_5566_7788;
    const CONST_VALUE: U128 = U128::from_u64(VALUE);
    const U128_VALUE: u128 = 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00;
    const CONST_U128_VALUE: U128 = U128::from_u128(U128_VALUE);

    #[test]
    fn smaller_primitive_constructors_are_const_and_zero_extend() {
        const FROM_U8: U128 = U128::from_u8(0x11);
        const FROM_U16: U128 = U128::from_u16(0x1122);
        const FROM_U32: U128 = U128::from_u32(0x1122_3344);

        assert_eq!(FROM_U8, U128::from_u128(0x11));
        assert_eq!(FROM_U16, U128::from_u128(0x1122));
        assert_eq!(FROM_U32, U128::from_u128(0x1122_3344));
    }

    #[test]
    fn from_u64_stores_little_endian_limbs() {
        let value = CONST_VALUE;

        #[cfg(target_pointer_width = "64")]
        assert_eq!(value.limbs, [Limb(VALUE), Limb(0)]);

        #[cfg(not(target_pointer_width = "64"))]
        assert_eq!(
            value.limbs,
            [Limb(0x5566_7788), Limb(0x1122_3344), Limb(0), Limb(0)]
        );
    }

    #[test]
    fn from_u64_accepts_the_smallest_supported_width() {
        let value = FixedBigUint::<{ 64 / crate::Word::BITS as usize }>::from_u64(VALUE);

        #[cfg(target_pointer_width = "64")]
        assert_eq!(value.limbs, [Limb(VALUE)]);

        #[cfg(not(target_pointer_width = "64"))]
        assert_eq!(value.limbs, [Limb(0x5566_7788), Limb(0x1122_3344)]);
    }

    #[test]
    fn from_traits_use_the_const_constructors() {
        assert_eq!(U128::from(0x11_u8), U128::from_u8(0x11));
        assert_eq!(U128::from(0x1122_u16), U128::from_u16(0x1122));
        assert_eq!(U128::from(0x1122_3344_u32), U128::from_u32(0x1122_3344));
        assert_eq!(U128::from(VALUE), CONST_VALUE);
        assert_eq!(U128::from(U128_VALUE), CONST_U128_VALUE);

        let into: U128 = VALUE.into();
        assert_eq!(into, CONST_VALUE);
    }

    #[test]
    fn from_u128_stores_little_endian_limbs() {
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            CONST_U128_VALUE.limbs,
            [Limb(0x99aa_bbcc_ddee_ff00), Limb(0x1122_3344_5566_7788)]
        );

        #[cfg(not(target_pointer_width = "64"))]
        assert_eq!(
            CONST_U128_VALUE.limbs,
            [
                Limb(0xddee_ff00),
                Limb(0x99aa_bbcc),
                Limb(0x5566_7788),
                Limb(0x1122_3344),
            ]
        );
    }
}
