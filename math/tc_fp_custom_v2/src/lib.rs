//! SEC and SM2 prime curves with their fields fixed at compile time, after Bouncy Castle's
//! `SecP*` and `SM2P256V1` classes; a rewrite of `tc_fp_custom`.

#![no_std]

extern crate alloc;

mod nat;
mod secp256k1_field;
mod secp256k1_field_element;
mod secp256r1_field;
mod secp256r1_field_element;
mod secp384r1_field;
mod secp384r1_field_element;
mod secp_ct_curve;
mod secp_ct_point;
mod secp_element;
mod secp_var_curve;
mod secp_var_point;

pub mod named_curves;

pub use secp_ct_curve::SecPCtCurve;
pub use secp_ct_point::SecPCtPoint;
pub use secp_var_curve::SecPVarCurve;
pub use secp_var_point::SecPVarPoint;
pub use secp256k1_field_element::SecP256K1FieldElement;
pub use secp256r1_field_element::SecP256R1FieldElement;
pub use secp384r1_field_element::SecP384R1FieldElement;
