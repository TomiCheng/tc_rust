//! Arbitrary-precision unsigned integers.

use alloc::vec::Vec;

use crate::Limb;

mod boxed;
mod from;

/// An unsigned integer whose precision grows as needed.
///
/// Limbs are stored in little-endian order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BigUint {
    limbs: Vec<Limb>,
}

impl BigUint {
    pub(crate) fn as_limbs(&self) -> &[Limb] {
        &self.limbs
    }

    pub(crate) fn from_limbs(mut limbs: Vec<Limb>) -> Self {
        while limbs.last() == Some(&Limb(0)) {
            limbs.pop();
        }

        Self { limbs }
    }
}
