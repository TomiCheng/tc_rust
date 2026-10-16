use super::scalar::KARATSUBA_CUTOFF;

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
}
