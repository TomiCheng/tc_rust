use super::scalar;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86;
use crate::reduce::Reducer;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use tc_runtime::intrinsics::x86::Pclmulqdq;

/// The multiplication backend, picked once at construction as BC's `CreateBinPolyMul` does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Multiplier {
    ScalarMedium,
    ScalarLarge,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    X86Medium(Pclmulqdq),
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    X86Large(Pclmulqdq),
}

impl Multiplier {
    /// PCLMULQDQ when the CPU has it, the scalar fallback otherwise.
    pub(crate) fn new(size: usize) -> Self {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if let Some(proof) = Pclmulqdq::detect() {
            return Self::pick_x86(size, proof);
        }
        Self::pick_scalar(size)
    }

    fn pick_scalar(size: usize) -> Self {
        if size < scalar::large::KARATSUBA_CUTOFF {
            Self::ScalarMedium
        } else {
            Self::ScalarLarge
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn pick_x86(size: usize, proof: Pclmulqdq) -> Self {
        if size < x86::large::KARATSUBA_CUTOFF {
            Self::X86Medium(proof)
        } else {
            Self::X86Large(proof)
        }
    }

    /// `z = x · y mod f`, all of `size(n)` limbs.
    pub(crate) fn multiply(&self, reducer: &Reducer, x: &[u64], y: &[u64], z: &mut [u64]) {
        match *self {
            Self::ScalarMedium => scalar::medium::multiply(reducer, x, y, z),
            Self::ScalarLarge => scalar::large::multiply(reducer, x, y, z),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Self::X86Medium(proof) => x86::medium::multiply(proof, reducer, x, y, z),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Self::X86Large(proof) => x86::large::multiply(proof, reducer, x, y, z),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Multiplier;

    #[test]
    fn each_backend_turns_to_karatsuba_at_its_own_cutoff() {
        assert_eq!(Multiplier::pick_scalar(7), Multiplier::ScalarMedium);
        assert_eq!(Multiplier::pick_scalar(8), Multiplier::ScalarLarge);

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if let Some(proof) = tc_runtime::intrinsics::x86::Pclmulqdq::detect() {
            assert_eq!(
                Multiplier::pick_x86(31, proof),
                Multiplier::X86Medium(proof)
            );
            assert_eq!(Multiplier::pick_x86(32, proof), Multiplier::X86Large(proof));
            assert_eq!(Multiplier::new(1), Multiplier::X86Medium(proof));
        }
    }
}
