//! Portable scalar multiplication backend.

mod kernels;
mod large;

pub use kernels::impl_mul;
pub(crate) use large::{
    impl_karatsuba, impl_karatsuba_with_leaf, karatsuba_scratch_size,
    karatsuba_scratch_size_with_cutoff,
};

/// Initial scalar Karatsuba cutoff in `u64` limbs.
///
/// This starts at BC's measured scalar cutoff and is intentionally a named
/// constant so the crate benchmark can retune it for Rust code generation.
pub const KARATSUBA_CUTOFF: usize = 8;
