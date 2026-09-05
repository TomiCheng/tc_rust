//! Portable scalar multiplication backend.

mod kernels;
#[cfg(feature = "alloc")]
mod large;

pub use kernels::impl_mul;
#[cfg(feature = "alloc")]
pub(crate) use large::{impl_karatsuba, karatsuba_scratch_size};
#[cfg(all(
    feature = "alloc",
    any(
        feature = "bench-internals",
        all(feature = "x86", any(target_arch = "x86", target_arch = "x86_64"))
    )
))]
pub(crate) use large::{impl_karatsuba_with_leaf, karatsuba_scratch_size_with_cutoff};

/// Measured scalar Karatsuba crossover in `u64` limbs.
///
/// Rust tuning across 6 through 32 limbs kept 8 in the best-performing group;
/// nearby cutoffs varied by only a few percent across operand sizes.
pub const KARATSUBA_CUTOFF: usize = 8;
