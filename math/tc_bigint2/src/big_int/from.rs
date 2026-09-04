//! Conversions into arbitrary-precision signed integers.

use alloc::vec::Vec;

use crate::{BigInt, FixedBigInt};

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
