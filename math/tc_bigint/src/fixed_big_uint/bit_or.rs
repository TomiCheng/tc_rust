//! Bitwise OR operations for [`FixedBigUint`].

use core::ops::{BitOr, BitOrAssign};

use crate::FixedBigUint;

impl<const N: usize> BitOr for FixedBigUint<N> {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self {
            limbs: self.limbs.bitor(&rhs.limbs),
        }
    }
}

crate::ops_forward::forward_binop_fixed!(BitOr, bitor, BitOrAssign, bitor_assign, FixedBigUint);
