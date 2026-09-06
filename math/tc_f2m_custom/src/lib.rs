#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod curves;
mod field;
mod fields;

pub use curves::*;
#[doc(hidden)]
pub use field::{BinaryFieldSpec, SpecializedBinaryField, SpecializedBinaryPoly};
pub use fields::*;
pub use tc_ec_core::{Curve, FieldElement, Point, scalar_mul, wnaf_mul, wnaf_mul_point};
pub use tc_f2m_curve::{WTauNafTable, generate_tau_naf, wtnaf_mul, wtnaf_mul_point};

#[cfg(test)]
mod tests;
