//! tc_algo 與 ASN.1 之間的序列化：金鑰的 SPKI 與 PKCS#8、`AlgorithmIdentifier` 的參數，給 X.509、
//! PKCS、CMS 這一族使用；OpenPGP 不經過這一層。

mod default_algo_asn1;
mod default_algo_asn1_builder;
mod default_algo_asn1_context;
mod der;
mod error;
pub mod private_key_info;
pub mod spki;
mod traits;

pub use default_algo_asn1_builder::DefaultAlgoAsn1Builder;
pub use default_algo_asn1_context::DefaultAlgoAsn1Context;
pub use error::AlgoAsn1Error;
pub use traits::{AlgoAsn1, AlgoAsn1Builder};
