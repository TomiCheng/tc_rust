//! ML-DSA（FIPS 204）簽章，移植自 Bouncy Castle 的 `MLDsaSigner` 與 `HashMLDsaSigner`：三組參數、
//! 金鑰與產生器，以及實作 `tc_signer` 的 signer。純軟體實作；雜湊用 `tc_keccak` 的 SHAKE。
//!
//! ```
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_ml_dsa::{MlDsaKeyGenerationParams, MlDsaKeyPairGenerator, MlDsaParameters, MlDsaSigner};
//! use tc_signer::{Signer, SignerInit};
//!
//! let params = MlDsaParameters::ML_DSA_65;
//! let mut rng = rand::rng();
//! let mut generator = MlDsaKeyPairGenerator::new();
//! generator.init(MlDsaKeyGenerationParams::new(params, &mut rng))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! let mut signer = MlDsaSigner::new(params, rand::rng());
//! signer.init(&private_key)?;
//! signer.update(b"attack at dawn")?;
//! let mut signature = vec![0; signer.max_signature_size()];
//! signer.generate_signature(&mut signature)?;
//!
//! let mut verifier = MlDsaSigner::new(params, rand::rng());
//! verifier.init(&public_key)?;
//! verifier.update(b"attack at dawn")?;
//! assert!(verifier.verify_signature(&signature)?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod engine;
mod error;
mod key_pair_generator;
mod keys;
mod ntt;
mod params;
mod poly;
mod reduce;
mod rounding;
mod signer;

pub use error::MlDsaError;
pub use key_pair_generator::{MlDsaKeyGenerationParams, MlDsaKeyPairGenerator};
pub use keys::{MlDsaPrivateKey, MlDsaPublicKey};
pub use params::MlDsaParameters;
pub use signer::{Deterministic, HashMlDsaSigner, MlDsaSigner};
