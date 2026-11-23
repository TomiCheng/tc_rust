//! Public keys to and from `SubjectPublicKeyInfo`.
//!
//! ```
//! use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};
//! use tc_algo_asn1::{AlgoAsn1Builder, DefaultAlgoAsn1Builder};
//!
//! let algo = DefaultAlgoBuilder::default().build();
//! let asn1 = DefaultAlgoAsn1Builder::default().build();
//!
//! // An Ed25519 key pair
//! let pair = algo.key_pair_generator().get_by_name("Ed25519")?.generate()?;
//!
//! // The public key as an SPKI, such as a certificate or a request carries
//! let spki = asn1.spki().encode(pair.public())?;
//! assert_eq!(spki.algorithm().algorithm().to_string(), "1.3.101.112");
//!
//! // The public key read back from an SPKI, ready for tc_algo to verify with
//! let public_key = asn1.spki().decode(&spki)?;
//! # assert_eq!(asn1.spki().encode(public_key.as_ref())?, spki);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod algo;
mod default_spki_provider;
mod spki_entry;
mod spki_provider;

pub(crate) use algo::{BUILT_IN, CreateRows};
pub(crate) use default_spki_provider::DefaultSpkiProvider;
pub use spki_entry::SpkiEntry;
pub use spki_provider::SpkiProvider;
