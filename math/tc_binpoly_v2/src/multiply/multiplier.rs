use super::scalar;
use super::scalar::large::KARATSUBA_CUTOFF;
use crate::reduce::Reducer;

/// The multiplication backend, picked once at construction as BC's `CreateBinPolyMul` does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Multiplier {
    ScalarMedium,
    ScalarLarge,
}

impl Multiplier {
    pub(crate) fn new(size: usize) -> Self {
        if size < KARATSUBA_CUTOFF {
            Self::ScalarMedium
        } else {
            Self::ScalarLarge
        }
    }

    /// `z = x · y mod f`, all of `size(n)` limbs.
    pub(crate) fn multiply(&self, reducer: &Reducer, x: &[u64], y: &[u64], z: &mut [u64]) {
        match self {
            Self::ScalarMedium => scalar::medium::multiply(reducer, x, y, z),
            Self::ScalarLarge => todo!("scalar Karatsuba multiplier"),
        }
    }
}
