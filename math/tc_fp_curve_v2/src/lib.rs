//! Prime-field short-Weierstrass curves; a rewrite of `tc_fp_curve`.

#![no_std]
extern crate alloc;

mod fp_ct_curve;
mod fp_ct_point;
mod fp_ct_precomputed;
mod fp_error;
mod fp_field;
mod fp_field_element;
mod fp_var_curve;
mod fp_var_point;
mod fp_var_precomputed;
mod sec1;

pub mod named_curves;

pub use fp_ct_curve::FpCtCurve;
pub use fp_ct_point::FpCtPoint;
pub use fp_ct_precomputed::FpCtPrecomputed;
pub use fp_error::FpError;
pub use fp_field::FpField;
pub use fp_field_element::FpFieldElement;
pub use fp_var_curve::FpVarCurve;
pub use fp_var_point::FpVarPoint;
pub use fp_var_precomputed::FpVarPrecomputed;
