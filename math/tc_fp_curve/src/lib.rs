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
#[cfg(test)]
mod wnaf_tests;

pub use fp_curve::FpCurve;
pub use fp_field_element::FpFieldElement;
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub use fp_field_element::{inversion_count, reset_inversion_count};
pub use fp_point::FpPoint;
pub use integer::FpInteger;
pub use tc_ec_core::{
    CoordinateSystem, Curve, FieldElement, Point, PointDecodeError, PointEncodeError,
    PrimeFieldElement, WNafTable, generate_compact_window_naf, generate_naf, generate_window_naf,
    get_naf_weight, get_window_size, scalar_mul, wnaf_mul, wnaf_mul_point,
};
