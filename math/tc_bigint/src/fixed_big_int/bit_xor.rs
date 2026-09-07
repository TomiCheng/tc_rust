//! Bitwise XOR operations for [`FixedBigInt`].

use crate::FixedBigInt;
use core::ops::{BitXor, BitXorAssign};

impl<const N: usize> BitXor for FixedBigInt<N> {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self {
            limbs: self.limbs.bitxor(&rhs.limbs),
        }
    }
}

crate::ops_forward::forward_binop_fixed!(BitXor, bitxor, BitXorAssign, bitxor_assign, FixedBigInt);
