//! Binary-polynomial arithmetic over `GF(2)`.
//!
//! A polynomial is packed into little-endian `u64` limbs: bit `i` is the
//! coefficient of `x^i`. The crate currently provides the scalar backend and
//! generic, correctness-first reducers for binomial, trinomial, and
//! pentanomial moduli.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod binary_poly;
mod error;
mod fixed_binary_poly;
mod invert;
mod multiplier;
mod ops;
mod reduce;
pub mod scalar;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;

pub use binary_poly::BinaryPoly;
pub use error::BinPolyError;
pub use fixed_binary_poly::FixedBinaryPoly;
pub use invert::{BinPolyInv, ItohTsujii};
pub use multiplier::{BinPolyMul, BinPolyMulBase, BinPolyMultiplier, STACK_ALLOC_CUTOFF};
pub use ops::{
    add, add_to, bit_length_var, clear, copy, equal_to, equal_to_one, equal_to_zero, one, size,
    zero,
};
pub use reduce::Reduce;

/// Largest polynomial degree accepted by the construction factories.
pub const MAX_N: usize = 1 << 20;
