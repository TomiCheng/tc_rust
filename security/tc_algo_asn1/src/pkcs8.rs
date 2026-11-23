//! Private keys to and from PKCS#8 `PrivateKeyInfo`.
//!
//! ```
//! use tc_algo::params::generate::EcKeyGenParams;
//! use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};
//! use tc_algo_asn1::{AlgoAsn1Builder, DefaultAlgoAsn1Builder};
//! use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
//! use tc_asn1_pkcs::PrivateKeyInfo;
//!
//! let algo = DefaultAlgoBuilder::default().build();
//! let asn1 = DefaultAlgoAsn1Builder::default().build();
//!
//! // A P-256 key pair
//! let mut generator = algo.key_pair_generator().get_by_name("EC")?;
//! generator.init(&EcKeyGenParams::from_oid("1.2.840.10045.3.1.7".parse()?))?;
//! let pair = generator.generate()?;
//!
//! // The private key as PKCS#8, then as DER to store
//! let info = asn1.pkcs8().encode(pair.private())?;
//! let der = info.encode_to_vec(&EncodingOptions::DER)?;
//!
//! // The PrivateKeyInfo read back from the DER, then the private key from it
//! let (_, info) = PrivateKeyInfo::decode(&der, &DecodingOptions::default())?;
//! let private_key = asn1.pkcs8().decode(&info)?;
//! # assert_eq!(asn1.pkcs8().encode(private_key.as_ref())?, info);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod algo;
mod default_pkcs8_provider;
mod pkcs8_entry;
mod pkcs8_provider;

pub(crate) use algo::{BUILT_IN, CreateRows};
pub(crate) use default_pkcs8_provider::DefaultPkcs8Provider;
pub use pkcs8_entry::Pkcs8Entry;
pub use pkcs8_provider::Pkcs8Provider;
