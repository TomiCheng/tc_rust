//! SLH-DSA（FIPS 205）簽章，移植自 Bouncy Castle 的 `SlhDsaSigner` 與 `HashSlhDsaSigner`：十二組
//! 參數、金鑰與產生器，以及實作 `tc_signer` 的 signer。純軟體實作；雜湊用 `tc_sha` 與
//! `tc_keccak`。
//!
//! ```
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_signer::{Signer, SignerInit};
//! use tc_slh_dsa::{SlhDsaKeyGenerationParams, SlhDsaKeyPairGenerator, SlhDsaParameters, SlhDsaSigner};
//!
//! let params = SlhDsaParameters::SHAKE_128F;
//! let mut rng = rand::rng();
//! let mut generator = SlhDsaKeyPairGenerator::new();
//! generator.init(SlhDsaKeyGenerationParams::new(params, &mut rng))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! let mut signer = SlhDsaSigner::new(params, rand::rng());
//! signer.init(&private_key)?;
//! signer.update(b"attack at dawn")?;
//! let mut signature = vec![0; signer.max_signature_size()];
//! signer.generate_signature(&mut signature)?;
//!
//! let mut verifier = SlhDsaSigner::new(params, rand::rng());
//! verifier.init(&public_key)?;
//! verifier.update(b"attack at dawn")?;
//! assert!(verifier.verify_signature(&signature)?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod adrs;
mod engine;
mod error;
mod hash;
mod key_pair_generator;
mod keys;
mod params;
mod signer;
mod tree;

pub use error::SlhDsaError;
pub use key_pair_generator::{SlhDsaKeyGenerationParams, SlhDsaKeyPairGenerator};
pub use keys::{SlhDsaPrivateKey, SlhDsaPublicKey};
pub use params::SlhDsaParameters;
pub use signer::{Deterministic, HashSlhDsaSigner, SlhDsaSigner};
