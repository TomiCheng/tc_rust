//! Arbitrary-precision unsigned integers.

use alloc::vec::Vec;

#[cfg(test)]
use crate::ConversionError;
use crate::limb::slice;
use crate::traits::{One, Unsigned, Zero};
use crate::{Limb, Zeroize};

mod add;
mod array;
mod bit_and;
// An unbounded unsigned integer has no finite-width bitwise complement.
mod bit_or;
mod bit_xor;
mod bits;
mod cmp;
mod div;
mod from;
mod gcd;
mod invert_mod;
mod mul;
mod pow;
mod shl;
mod shr;
mod str;
mod sub;

/// An unsigned integer whose precision grows as needed.
///
/// Limbs are stored from least significant to most significant. Zero has an
/// empty limb vector; non-zero values never contain redundant high zero limbs.
///
/// [`Zeroize`] overwrites the live limbs before clearing their length, restoring
/// canonical zero while retaining the allocation. Spare capacity, earlier
/// allocations left by growth, and other copies are not erased. This storage
/// type offers explicit erasure, not the [`crate::ZeroizeOnDrop`] policy.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct BigUint {
    limbs: Vec<Limb>,
}

impl Zeroize for BigUint {
    fn zeroize(&mut self) {
        // Wipe while the live elements are still accessible, then restore
        // canonical zero. Only the current live slice is covered.
        self.limbs.zeroize();
        self.limbs.clear();
    }
}

impl BigUint {
    pub(crate) fn from_limbs(mut limbs: Vec<Limb>) -> Self {
        slice::normalize(&mut limbs);
        Self { limbs }
    }

    /// Borrows the canonical little-endian limbs.
    pub(crate) fn as_limbs(&self) -> &[Limb] {
        &self.limbs
    }

    /// Returns whether the value is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }
}

impl Zero for BigUint {
    fn zero() -> Self {
        Self::default()
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}

impl One for BigUint {
    fn one() -> Self {
        Self::from(1_u8)
    }
}

impl Unsigned for BigUint {}

#[cfg(test)]
mod tests;
