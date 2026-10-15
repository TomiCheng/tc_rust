//! Binary-polynomial arithmetic over GF(2); a rewrite of `tc_binpoly`.

#![no_std]
extern crate alloc;

mod bin_field;
mod fixed_bin_poly;
mod padded_bin_poly;

mod errors;
mod traits;
mod reduce;
mod invert;

pub use bin_field::BinField;
pub use fixed_bin_poly::FixedBinPoly;
pub use padded_bin_poly::PaddedBinPoly;
pub use errors::BinPolyError;
pub(crate) use reduce::Reducer;