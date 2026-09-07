//! Bitwise OR operations for [`FixedBigUint`].

use core::ops::{BitOr, BitOrAssign};

use crate::{FixedBigUint, Limb};

impl<const N: usize> BitOr for FixedBigUint<N> {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self {
            limbs: crate::LimbArray::new(core::array::from_fn(|index| {
                Limb::new(
                    self.limbs.as_limbs()[index].to_word() | rhs.limbs.as_limbs()[index].to_word(),
                )
            })),
        }
    }
}

crate::ops_forward::forward_binop_fixed!(BitOr, bitor, BitOrAssign, bitor_assign, FixedBigUint);
