//! Bitwise XOR operations for [`FixedBigInt`].

use crate::{FixedBigInt, Limb};
use core::ops::{BitXor, BitXorAssign};

impl<const N: usize> BitXor for FixedBigInt<N> {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self {
            limbs: crate::LimbArray::new(core::array::from_fn(|index| {
                Limb::new(
                    self.limbs.as_limbs()[index].to_word() ^ rhs.limbs.as_limbs()[index].to_word(),
                )
            })),
        }
    }
}

crate::ops_forward::forward_binop_fixed!(BitXor, bitxor, BitXorAssign, bitxor_assign, FixedBigInt);
