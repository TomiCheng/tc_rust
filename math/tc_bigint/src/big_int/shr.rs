//! Right shifts for [`BigInt`].

use core::ops::{Shr, ShrAssign};

use crate::traits::CheckedShr;
use crate::{BigInt, limb::slice};

impl Shr<usize> for &BigInt {
    type Output = BigInt;
    fn shr(self, rhs: usize) -> BigInt {
        let (negative, magnitude) = self.sign_magnitude();
        let discarded = negative && slice::truncated_bits_are_nonzero(&magnitude, rhs);
        let mut shifted = slice::shr(&magnitude, rhs);
        if discarded {
            slice::add_small(&mut shifted, 1);
        }
        BigInt::from_sign_magnitude(negative, shifted)
    }
}

impl Shr<usize> for BigInt {
    type Output = BigInt;
    fn shr(self, rhs: usize) -> BigInt {
        &self >> rhs
    }
}

impl CheckedShr for BigInt {
    fn checked_shr(&self, rhs: u32) -> Option<Self> {
        Some(self >> rhs as usize)
    }
}

impl ShrAssign<usize> for BigInt {
    fn shr_assign(&mut self, rhs: usize) {
        *self = &*self >> rhs;
    }
}
