//! Left shifts for [`BigInt`].

use core::ops::{Shl, ShlAssign};

use crate::traits::CheckedShl;
use crate::{BigInt, limb::slice};

impl Shl<usize> for &BigInt {
    type Output = BigInt;
    fn shl(self, rhs: usize) -> BigInt {
        let (negative, magnitude) = self.sign_magnitude();
        BigInt::from_sign_magnitude(negative, slice::shl(&magnitude, rhs))
    }
}

impl Shl<usize> for BigInt {
    type Output = BigInt;
    fn shl(self, rhs: usize) -> BigInt {
        &self << rhs
    }
}

impl CheckedShl for BigInt {
    fn checked_shl(&self, rhs: u32) -> Option<Self> {
        Some(self << rhs as usize)
    }
}

impl ShlAssign<usize> for BigInt {
    fn shl_assign(&mut self, rhs: usize) {
        *self = &*self << rhs;
    }
}
