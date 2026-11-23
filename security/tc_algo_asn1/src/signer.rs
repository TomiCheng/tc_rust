//! Signers of tc_algo by the `AlgorithmIdentifier` a certificate, a CRL or a `SignerInfo`
//! records: by name to sign, with the `AlgorithmIdentifier` to write, and by the one read to verify.
//!
//! ```
//! use tc_algo::params::generate::EcKeyGenParams;
//! use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};
//! use tc_algo_asn1::{AlgoAsn1Builder, DefaultAlgoAsn1Builder};
//!
//! let algo = DefaultAlgoBuilder::default().build();
//! let asn1 = DefaultAlgoAsn1Builder::default().build();
//!
//! // A P-256 key pair
//! let mut generator = algo.key_pair_generator().get_by_name("EC")?;
//! generator.init(&EcKeyGenParams::from_oid("1.2.840.10045.3.1.7".parse()?))?;
//! let pair = generator.generate()?;
//!
//! // Signing: the AlgorithmIdentifier goes into the TBS before it is signed
//! let mut signer = asn1.signer().get_by_name("SHA-256withECDSA")?;
//! signer.init(pair.private())?;
//! let algorithm = signer.algorithm().clone();
//! signer.update(b"to be signed")?;
//! let signature = signer.sign()?;
//!
//! // Verifying: the signer the recorded AlgorithmIdentifier calls for
//! let mut verifier = asn1.signer().get_by_id(&algorithm)?;
//! verifier.init(pair.public())?;
//! verifier.update(b"to be signed")?;
//! assert!(verifier.verify(&signature)?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod algo;
mod default_signer;
mod default_signer_provider;
mod signer_entry;
mod signer_provider;
mod signer_trait;

pub(crate) use algo::{BUILT_IN, CreateRows};
pub(crate) use default_signer::DefaultSigner;
pub(crate) use default_signer_provider::DefaultSignerProvider;
pub use signer_entry::SignerEntry;
pub use signer_provider::SignerProvider;
pub use signer_trait::Signer;
