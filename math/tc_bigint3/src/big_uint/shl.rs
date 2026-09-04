//! Left shifts for [`BigUint`].

use core::ops::{Shl, ShlAssign};

use crate::traits::CheckedShl;
use crate::{BigUint, arithmetic};

impl Shl<usize> for &BigUint {
    type Output = BigUint;

    fn shl(self, rhs: usize) -> Self::Output {
        BigUint::from_limbs(arithmetic::shl(&self.limbs, rhs))
    }
}

impl Shl<usize> for BigUint {
    type Output = BigUint;

    fn shl(self, rhs: usize) -> Self::Output {
        &self << rhs
    }
}

impl CheckedShl for BigUint {
    fn checked_shl(&self, rhs: u32) -> Option<Self> {
        Some(self << rhs as usize)
    }
}

impl ShlAssign<usize> for BigUint {
    fn shl_assign(&mut self, rhs: usize) {
        *self = &*self << rhs;
    }
}
