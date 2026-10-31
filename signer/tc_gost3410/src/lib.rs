//! GOST R 34.10-94 簽章，移植自 Bouncy Castle 的 `Gost3410Signer`，實作 `tc_dsa` 的 `Dsa`。
//! 參數與金鑰來自 `tc_gost3410_key`；要簽整則訊息時，用 `tc_dsa` 的 `Gost3410DigestSigner`
//! 包上 GOST R 34.11 雜湊。
//!
//! ```
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_dsa::Gost3410DigestSigner;
//! use tc_gost3410::Gost3410Signer;
//! use tc_gost3410_key::{
//!     Gost3410KeyGenerationParams, Gost3410KeyPairGenerator, Gost3410ParametersGenerator,
//! };
//! use tc_gost3411::Gost3411Digest;
//! use tc_signer::{Signer, SignerInit};
//!
//! // 參數與金鑰對（真正使用時是 1024 位元的程序 B）。
//! let mut rng = rand::rng();
//! let mut parameters = Gost3410ParametersGenerator::new();
//! parameters.init(512, 1, &mut rng)?;
//! let params = parameters.generate_parameters()?;
//! let mut rng = rand::rng();
//! let mut generator = Gost3410KeyPairGenerator::new();
//! generator.init(Gost3410KeyGenerationParams::new(params, &mut rng))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! // 以 GOST R 34.11-94 雜湊簽章，簽章是 s ‖ r。
//! let mut signer = Gost3410DigestSigner::new(Gost3410Signer::new(rand::rng()), Gost3411Digest::new());
//! signer.init(&private_key)?;
//! signer.update(b"hello")?;
//! let mut signature = vec![0; signer.max_signature_size()];
//! let length = signer.generate_signature(&mut signature)?;
//!
//! let mut verifier =
//!     Gost3410DigestSigner::new(Gost3410Signer::new(rand::rng()), Gost3411Digest::new());
//! verifier.init(&public_key)?;
//! verifier.update(b"hello")?;
//! assert!(verifier.verify_signature(&signature[..length])?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod error;
mod signer;

pub use error::Gost3410SignerError;
pub use signer::Gost3410Signer;
