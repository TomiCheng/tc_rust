//! Conversions from primitive unsigned integers.

use crate::{FixedBigUint, Limb, Word};

impl<const N: usize> FixedBigUint<N> {
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
}

impl<const N: usize> From<u64> for FixedBigUint<N> {
    #[inline]
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::{FixedBigUint, Limb, U128};

    const VALUE: u64 = 0x1122_3344_5566_7788;
    const CONST_VALUE: U128 = U128::from_u64(VALUE);

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
    fn from_u64_trait_uses_the_const_constructor() {
        let from = U128::from(VALUE);
        let into: U128 = VALUE.into();

        assert_eq!(from, CONST_VALUE);
        assert_eq!(into, CONST_VALUE);
    }
}
