//! Bitwise AND operations for [`FixedBigInt`].

use crate::FixedBigInt;
use core::ops::{BitAnd, BitAndAssign};

impl<const N: usize> BitAnd for FixedBigInt<N> {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self {
            limbs: self.limbs.bitand(&rhs.limbs),
        }
    }
}

crate::ops_forward::forward_binop_fixed!(BitAnd, bitand, BitAndAssign, bitand_assign, FixedBigInt);
