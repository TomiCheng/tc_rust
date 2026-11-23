//! The ASN.1 side of tc_algo: keys as `SubjectPublicKeyInfo` and PKCS#8, and the parameters
//! of `AlgorithmIdentifier`, for the X.509, PKCS and CMS crates. OpenPGP does not go through it.

mod default_algo_asn1;
mod default_algo_asn1_builder;
mod default_algo_asn1_context;
mod der;
pub mod digest;
mod error;
pub mod mac;
pub mod pkcs8;
pub mod signer;
pub mod spki;
mod traits;

pub use default_algo_asn1_builder::DefaultAlgoAsn1Builder;
pub use default_algo_asn1_context::DefaultAlgoAsn1Context;
pub use error::AlgoAsn1Error;
pub use traits::{AlgoAsn1, AlgoAsn1Builder};
