//! Fixed-precision signed integers.

use crate::Limb;

mod add;
mod boxed;
mod from;

/// A two's-complement signed integer containing exactly `N` little-endian limbs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedBigInt<const N: usize> {
    limbs: [Limb; N],
}

impl<const N: usize> FixedBigInt<N> {
    pub(crate) const fn as_limbs(&self) -> &[Limb; N] {
        &self.limbs
    }

    pub(crate) const fn into_limbs(self) -> [Limb; N] {
        self.limbs
    }
}
