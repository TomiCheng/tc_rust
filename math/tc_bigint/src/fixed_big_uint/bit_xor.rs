//! Bitwise XOR operations for [`FixedBigUint`].

use core::ops::{BitXor, BitXorAssign};

use crate::FixedBigUint;

impl<const N: usize> BitXor for FixedBigUint<N> {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self {
            limbs: self.limbs.bitxor(&rhs.limbs),
        }
    }
}

crate::ops_forward::forward_binop_fixed!(BitXor, bitxor, BitXorAssign, bitxor_assign, FixedBigUint);
