#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod fp_curve;
mod fp_field_element;
mod fp_point;
mod integer;
pub mod named_curves;
mod traits;

pub use fp_curve::FpCurve;
pub use fp_field_element::FpFieldElement;
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub use fp_field_element::{inversion_count, reset_inversion_count};
pub use fp_point::FpPoint;
pub use integer::FpInteger;
pub use tc_ec_core::{
    CoordinateSystem, Curve, FieldElement, Point, PointDecodeError, PrimeFieldElement, scalar_mul,
};
