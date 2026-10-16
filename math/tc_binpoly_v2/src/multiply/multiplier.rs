/// The multiplication backend, picked once at construction as BC's `CreateBinPolyMul` does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Multiplier {
    ScalarMedium,
    ScalarLarge,
}

/// BC's scalar `Large.KaratsubaCutoff`, in limbs.
const SCALAR_KARATSUBA_CUTOFF: usize = 8;

impl Multiplier {
    pub(crate) fn new(size: usize) -> Self {
        if size < SCALAR_KARATSUBA_CUTOFF {
            Self::ScalarMedium
        } else {
            Self::ScalarLarge
        }
    }
}
