//! Bitwise AND operations for [`FixedBigUint`].

use core::ops::{BitAnd, BitAndAssign};

use crate::{FixedBigUint, Limb};

impl<const N: usize> BitAnd for FixedBigUint<N> {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self {
            limbs: crate::LimbArray::new(core::array::from_fn(|index| {
                Limb::new(
                    self.limbs.as_limbs()[index].to_word() & rhs.limbs.as_limbs()[index].to_word(),
                )
            })),
        }
    }
}

crate::ops_forward::forward_binop_fixed!(BitAnd, bitand, BitAndAssign, bitand_assign, FixedBigUint);
