//! Bitwise AND operations for [`FixedBigUint`].

use core::ops::{BitAnd, BitAndAssign};

use crate::FixedBigUint;

impl<const N: usize> BitAnd for FixedBigUint<N> {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self {
            limbs: self.limbs.bitand(&rhs.limbs),
        }
    }
}

crate::ops_forward::forward_binop_fixed!(BitAnd, bitand, BitAndAssign, bitand_assign, FixedBigUint);
