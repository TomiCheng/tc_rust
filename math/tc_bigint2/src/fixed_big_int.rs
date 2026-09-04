//! Fixed-precision signed integers.

use crate::Limb;

/// A two's-complement signed integer containing exactly `N` little-endian limbs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedBigInt<const N: usize> {
    limbs: [Limb; N],
}
