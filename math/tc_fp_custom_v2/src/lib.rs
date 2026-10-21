//! SEC and SM2 prime curves with their fields fixed at compile time, after Bouncy Castle's
//! `SecP*` and `SM2P256V1` classes; a rewrite of `tc_fp_custom`.

#![no_std]

extern crate alloc;

mod mod_inverse;
mod nat;
mod nat64;
mod sec1;
mod secp128r1_field;
mod secp128r1_field_element;
mod secp160r1_field;
mod secp160r1_field_element;
mod secp160r2_field;
mod secp160r2_field_element;
mod secp192k1_field;
mod secp192k1_field_element;
mod secp192r1_field;
mod secp192r1_field_element;
mod secp224k1_field;
mod secp224k1_field_element;
mod secp224r1_field;
mod secp224r1_field_element;
mod secp256k1_field;
mod secp256k1_field_element;
mod secp256r1_field;
mod secp256r1_field_element;
mod secp384r1_field;
mod secp384r1_field_element;
mod secp521r1_field;
mod secp521r1_field_element;
mod secp_ct_curve;
mod secp_ct_point;
mod secp_ct_precomputed;
mod secp_element;
mod secp_error;
mod secp_var_curve;
mod secp_var_point;
mod secp_var_precomputed;
mod sm2p256v1_field;
mod sm2p256v1_field_element;

pub mod named_curves;

pub use secp_ct_curve::SecPCtCurve;
pub use secp_ct_point::SecPCtPoint;
pub use secp_ct_precomputed::SecPCtPrecomputed;
pub use secp_error::SecPError;
pub use secp_var_curve::SecPVarCurve;
pub use secp_var_point::SecPVarPoint;
pub use secp_var_precomputed::SecPVarPrecomputed;
pub use secp128r1_field_element::SecP128R1FieldElement;
pub use secp160r1_field_element::SecP160R1FieldElement;
pub use secp160r2_field_element::SecP160R2FieldElement;
pub use secp192k1_field_element::SecP192K1FieldElement;
pub use secp192r1_field_element::SecP192R1FieldElement;
pub use secp224k1_field_element::SecP224K1FieldElement;
pub use secp224r1_field_element::SecP224R1FieldElement;
pub use secp256k1_field_element::SecP256K1FieldElement;
pub use secp256r1_field_element::SecP256R1FieldElement;
pub use secp384r1_field_element::SecP384R1FieldElement;
pub use secp521r1_field_element::SecP521R1FieldElement;
pub use sm2p256v1_field_element::SM2P256V1FieldElement;
