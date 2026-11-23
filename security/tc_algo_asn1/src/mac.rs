//! MACs of tc_algo by the `AlgorithmIdentifier` an `AuthenticatedData` records: by name to write
//! one, and by the one read to check it.
//!
//! ```
//! use tc_algo::params::key::KeyOwned;
//! use tc_algo_asn1::{AlgoAsn1Builder, DefaultAlgoAsn1Builder};
//!
//! let asn1 = DefaultAlgoAsn1Builder::default().build();
//! let key = KeyOwned::new(vec![0x0b; 32]);
//!
//! // Writing: the AlgorithmIdentifier to record beside the tag
//! let mut mac = asn1.mac().get_by_name("HMAC-SHA256")?;
//! mac.init(&key)?;
//! let algorithm = mac.algorithm().clone();
//! mac.update(b"content")?;
//! let tag = mac.finalize()?;
//!
//! // Reading: the MAC the recorded AlgorithmIdentifier calls for
//! let mut mac = asn1.mac().get_by_id(&algorithm)?;
//! mac.init(&key)?;
//! mac.update(b"content")?;
//! assert!(mac.verify(&tag)?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod algo;
mod asn1_mac;
mod default_asn1_mac;
mod default_mac_provider;
mod mac_entry;
mod mac_provider;

pub(crate) use algo::{BUILT_IN, CreateRows};
pub use asn1_mac::Asn1Mac;
pub(crate) use default_asn1_mac::DefaultAsn1Mac;
pub(crate) use default_mac_provider::DefaultMacProvider;
pub use mac_entry::MacEntry;
pub use mac_provider::MacProvider;
pub use tc_macs::MacInit;
