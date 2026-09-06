#![no_std]

//! Generic elliptic-curve mathematics. Public-scalar algorithms are variable time.
//!
//! Bouncy Castle's `field/` descriptor hierarchy (`IFiniteField`, extension fields,
//! and polynomial descriptors) is intentionally not ported: the associated types
//! in `Curve`, `FieldElement`, and `BinaryFieldElement` express the arithmetic
//! contracts. ASN.1 field-description queries belong in an encoding layer.
//! Runtime Fp/F2m type tests and the `Nat128..Nat576` class family are likewise
//! replaced by Rust types and const-generic integers. AES GF(256) belongs in crypto.

extern crate alloc;

mod algorithms;
mod binary_field_element;
mod secret;
pub use secret::{
    Choice, ConditionallySelectable, ConstantTimeEq, ECLookupTable, SecretCurve, SecretField,
    SecretPoint, multiply_secret, sum_of_two_multiplies_secret,
};
mod endomorphism;
mod fixed_point;
pub use endomorphism::{GlvEndomorphism, PointMap, ScalePointMap, glv_mul};
pub use fixed_point::FixedPointTable;
mod coordinate_system;
mod curve;
mod field_element;
mod point;
mod point_decode_error;
mod point_encode_error;
mod prime_field_element;
mod scalar_mul;
mod wnaf;

pub use algorithms::{
    AlgorithmError, clean_point, import_point, montgomery_trick, normalize_all, shamirs_trick,
    sum_of_multiplies, sum_of_two_multiplies, validate_point,
};
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
    WNafTable, generate_compact_window_naf, generate_jsf, generate_naf, generate_window_naf,
    get_naf_weight, get_window_size, wnaf_mul, wnaf_mul_point,
};
