//! RSA signatures, ported from Bouncy Castle C#.
//!
//! Alice signs a message with her private key, and anyone with her public key can check it:
//!
//! ```
//! use tc_asn1_pkcs::Pkcs1Algorithm;
//! use tc_asn1_x509::alg::AlgorithmIdentifier;
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_rsa::{RsaEngine, RsaKeyGenerationParamsOwned, RsaKeyGenerator};
//! use tc_rsa_signer::RsaDigestSigner;
//! use tc_sha::Sha256Digest;
//! use tc_signer::{Signer, SignerInit};
//!
//! // Alice makes a 2048-bit key pair.
//! let mut generator = RsaKeyGenerator::new();
//! generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! // The signer hashes with SHA-256, and names it in the DigestInfo it signs.
//! let sha256 = AlgorithmIdentifier::with_null(Pkcs1Algorithm::SHA256.oid());
//! let mut signer = RsaDigestSigner::new(RsaEngine::new(), Sha256Digest::new(), sha256);
//!
//! // She signs with her private key...
//! signer.init(&private_key)?;
//! signer.update(b"attack at dawn")?;
//! let mut signature = [0; 256];
//! let len = signer.generate_signature(&mut signature)?;
//!
//! // ...and Bob checks it with her public key.
//! signer.init(&public_key)?;
//! signer.update(b"attack at dawn")?;
//! assert!(signer.verify_signature(&signature[..len])?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod error;
pub mod iso_trailers;
mod mask_generator;
mod pss_error;
mod pss_signer;
mod rsa_digest_signer;
mod x931_error;
mod x931_signer;

pub use error::RsaDigestSignerError;
pub use mask_generator::{MaskGenerator, Mgf1, XofMgf};
pub use pss_error::PssSignerError;
pub use pss_signer::PssSigner;
pub use rsa_digest_signer::RsaDigestSigner;
pub use x931_error::X931SignerError;
pub use x931_signer::X931Signer;
