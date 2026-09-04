//! Right shifts for [`BigUint`].

use core::ops::{Shr, ShrAssign};

use crate::traits::CheckedShr;
use crate::{BigUint, arithmetic};

impl Shr<usize> for &BigUint {
    type Output = BigUint;

    fn shr(self, rhs: usize) -> Self::Output {
        BigUint::from_limbs(arithmetic::shr(&self.limbs, rhs))
    }
}

impl Shr<usize> for BigUint {
    type Output = BigUint;

    fn shr(self, rhs: usize) -> Self::Output {
        &self >> rhs
    }
}

impl CheckedShr for BigUint {
    fn checked_shr(&self, rhs: u32) -> Option<Self> {
        Some(self >> rhs as usize)
    }
}

impl ShrAssign<usize> for BigUint {
    fn shr_assign(&mut self, rhs: usize) {
        *self = &*self >> rhs;
    }
}
