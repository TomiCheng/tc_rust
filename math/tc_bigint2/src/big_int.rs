//! Arbitrary-precision signed integers.

use crate::{BigUint, Sign};

/// A sign-and-magnitude integer whose precision grows as needed.
///
/// The magnitude uses little-endian limb order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BigInt {
    sign: Sign,
    magnitude: BigUint,
}
