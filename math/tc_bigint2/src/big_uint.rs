//! Arbitrary-precision unsigned integers.

use alloc::vec::Vec;

use crate::Limb;

/// An unsigned integer whose precision grows as needed.
///
/// Limbs are stored in little-endian order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BigUint {
    limbs: Vec<Limb>,
}
