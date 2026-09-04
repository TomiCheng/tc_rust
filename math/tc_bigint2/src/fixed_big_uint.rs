//! Fixed-precision unsigned integers.

use crate::Limb;

/// An unsigned integer containing exactly `N` little-endian limbs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedBigUint<const N: usize> {
    limbs: [Limb; N],
}
