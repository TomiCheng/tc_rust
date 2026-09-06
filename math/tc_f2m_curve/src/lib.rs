#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod f2m_curve;
mod f2m_field;
mod f2m_field_element;
mod f2m_point;
mod integer;
pub mod named_curves;
mod polynomial;
mod traits;

pub use f2m_curve::F2mCurve;
pub use f2m_field::{F2mField, ReductionPolynomial};
pub use f2m_field_element::F2mFieldElement;
pub use f2m_point::F2mPoint;
pub use integer::F2mInteger;
pub use polynomial::F2mPolynomial;
pub use tc_ec_core::{
    BinaryFieldElement, CoordinateSystem, Curve, FieldElement, Point, PointDecodeError, WNafTable,
    generate_compact_window_naf, generate_naf, generate_window_naf, get_naf_weight,
    get_window_size, scalar_mul, wnaf_mul, wnaf_mul_point,
};
