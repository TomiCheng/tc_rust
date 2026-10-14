//! Generic elliptic-curve traits; a rewrite of `tc_ec_core`.

#![no_std]

extern crate alloc;

mod coordinate_system;
mod traits;
mod errors;
pub mod algo;
pub mod wnaf;

pub use coordinate_system::CoordinateSystem;

pub use traits::BinaryFieldElement;
pub use traits::Curve;
pub use traits::FieldElement;
pub use traits::Point;
pub use traits::PrimeFieldElement;
pub use traits::Scalar;

pub use errors::PointDecodeError;
pub use errors::PointEncodeError;