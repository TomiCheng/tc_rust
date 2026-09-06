#![no_std]

extern crate alloc;

mod binary_field_element;
mod coordinate_system;
mod curve;
mod field_element;
mod point;
mod point_decode_error;
mod point_encode_error;
mod prime_field_element;
mod scalar_mul;
mod wnaf;

pub use binary_field_element::BinaryFieldElement;
pub use coordinate_system::CoordinateSystem;
pub use curve::Curve;
pub use field_element::FieldElement;
pub use point::Point;
pub use point_decode_error::PointDecodeError;
pub use point_encode_error::PointEncodeError;
pub use prime_field_element::PrimeFieldElement;
pub use scalar_mul::scalar_mul;
pub use wnaf::{
    WNafTable, generate_compact_window_naf, generate_naf, generate_window_naf, get_naf_weight,
    get_window_size, wnaf_mul, wnaf_mul_point,
};
