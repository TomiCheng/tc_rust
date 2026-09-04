//! Fixed-precision unsigned integers.

use crate::Limb;

mod boxed;
mod from;

/// An unsigned integer containing exactly `N` little-endian limbs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedBigUint<const N: usize> {
    limbs: [Limb; N],
}

impl<const N: usize> FixedBigUint<N> {
    pub(crate) const fn as_limbs(&self) -> &[Limb; N] {
        &self.limbs
    }

    pub(crate) const fn into_limbs(self) -> [Limb; N] {
        self.limbs
    }
}
