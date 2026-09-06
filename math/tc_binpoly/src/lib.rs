#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub mod bench_support;
#[cfg(feature = "alloc")]
mod binary_poly;
mod binary_poly_ops;
mod error;
mod fixed_binary_poly;
pub mod interleave;
#[cfg(feature = "alloc")]
mod invert;
mod multiplier;
mod ops;
mod reduce;
pub mod scalar;
#[cfg(all(feature = "x86", any(target_arch = "x86", target_arch = "x86_64")))]
mod x86;

#[cfg(feature = "alloc")]
pub use binary_poly::BinaryPoly;
pub use binary_poly_ops::BinaryPolyOps;
pub use error::BinPolyError;
pub use fixed_binary_poly::FixedBinaryPoly;
#[cfg(feature = "alloc")]
pub use invert::{BinPolyInv, ItohTsujii};
#[cfg(feature = "alloc")]
pub use multiplier::BinPolyMul;
pub use multiplier::{BinPolyMulBase, BinPolyMultiplier, STACK_ALLOC_CUTOFF};
pub use ops::{
    add, add_to, bit_length_var, clear, copy, equal_to, equal_to_one, equal_to_zero, one, size,
    zero,
};
pub use reduce::Reduce;

/// Largest polynomial degree accepted by the construction factories.
pub const MAX_N: usize = 1 << 20;
