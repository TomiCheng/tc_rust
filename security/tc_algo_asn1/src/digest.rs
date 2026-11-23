//! Digests of tc_algo by the `AlgorithmIdentifier` a `SignerInfo`, a `CertID` or a
//! `MessageImprint` records: by name to write one, by the one read to check it, and by the signature
//! algorithm that hashes with it.
//!
//! ```
//! use tc_algo_asn1::{AlgoAsn1Builder, DefaultAlgoAsn1Builder};
//!
//! let asn1 = DefaultAlgoAsn1Builder::default().build();
//!
//! // Writing: the AlgorithmIdentifier to record beside the hash
//! let mut digest = asn1.digest().get_by_name("SHA-256")?;
//! let algorithm = digest.algorithm().clone();
//! digest.try_update(b"content")?;
//! let hash = digest.finalize()?;
//!
//! // Reading: the digest the recorded AlgorithmIdentifier calls for
//! let mut digest = asn1.digest().get_by_id(&algorithm)?;
//! digest.try_update(b"content")?;
//! assert_eq!(digest.finalize()?, hash);
//!
//! // Signing in CMS: the digest the signature algorithm hashes with
//! let signer = asn1.signer().get_by_name("SHA-256withECDSA")?;
//! let digest = asn1.digest().get_by_signer(signer.algorithm())?;
//! assert_eq!(digest.algorithm(), &algorithm);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod algo;
mod asn1_digest;
mod default_asn1_digest;
mod default_digest_provider;
mod digest_entry;
mod digest_provider;

pub(crate) use algo::{BUILT_IN, CreateRows};
pub use asn1_digest::Asn1Digest;
pub(crate) use default_asn1_digest::DefaultAsn1Digest;
pub(crate) use default_digest_provider::DefaultDigestProvider;
pub use digest_entry::DigestEntry;
pub use digest_provider::DigestProvider;
pub use tc_digest::TryDigest;
