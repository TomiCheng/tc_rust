//! Conversions into arbitrary-precision unsigned integers.

use crate::{BigUint, FixedBigUint};

impl<const N: usize> From<FixedBigUint<N>> for BigUint {
    fn from(value: FixedBigUint<N>) -> Self {
        Self::from_limbs(value.into_limbs().into())
    }
}

#[cfg(test)]
mod tests {
    use crate::{BigUint, Limb, U128};

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
