//! Scalar (non-SIMD) backend for binary-polynomial multiplication.
//!
//! Mirrors Bouncy Castle's `Math.BinPoly.Scalar` namespace: the carryless-multiply
//! [`kernels`], the [`medium`] leaf operator, and this size-based backend chooser
//! ([`create`], = bc `Scalar.Backend.CreateBinPolyMul`). Karatsuba (`Large`) and a
//! hardware backend are later additions.

use alloc::boxed::Box;

use crate::binpoly::mul::BinPolyMul;
use crate::binpoly::reduce::Reduce;

mod kernels;
mod medium;

/// Builds the scalar multiply operator for `GF(2ⁿ)` with the given reducer,
/// choosing the implementation by size. Mirrors bc `Scalar.Backend.CreateBinPolyMul`.
// TODO(binpoly-large): route `size >= Karatsuba cutoff` to a `large::create`
// (Karatsuba recursion, bc `Scalar.Large`, only sect571 needs it) once ported; for
// now every size uses the Medium leaf.
pub(crate) fn create(n: usize, reduce: Box<dyn Reduce>) -> Box<dyn BinPolyMul> {
    medium::create(n, reduce)
}
