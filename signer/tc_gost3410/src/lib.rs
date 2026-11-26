//! GOST R 34.10-94，移植自 Bouncy Castle：`Gost3410Parameters`、`Gost3410ValidationParameters`、
//! 公私鑰、金鑰對產生器、群產生器（程序 A、A'、B、B'、C），以及實作 `tc_dsa` 的 `Dsa` 的
//! `Gost3410Signer`。要簽整則訊息時，用 `tc_dsa` 的 `Gost3410DigestSigner` 包上 GOST R 34.11
//! 雜湊。
//!
//! ```
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_dsa::Gost3410DigestSigner;
//! use tc_gost3410::{
//!     Gost3410GroupGenerator, Gost3410KeyGenerationParams, Gost3410KeyPairGenerator,
//!     Gost3410Signer,
//! };
//! use tc_gost3411::Gost3411Digest;
//! use tc_signer::{Signer, SignerInit};
//!
//! // 群：以程序 A 產生 512 位元的 p 與 256 位元的 q（真正使用時是 1024 位元的程序 B）。
//! let mut group_generator = Gost3410GroupGenerator::new(rand::rng());
//! group_generator.init(512, 1)?;
//! let params = group_generator.generate_group()?;
//!
//! // 簽章者的金鑰對：x 留在本地、drop 時清除，y 交給驗章者。
//! let mut generator = Gost3410KeyPairGenerator::new(rand::rng());
//! generator.init(&Gost3410KeyGenerationParams::new(params))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! // 簽章：以 GOST R 34.11-94 雜湊整則訊息，簽章是 s ‖ r。
//! let mut signer = Gost3410DigestSigner::new(Gost3410Signer::new(rand::rng()), Gost3411Digest::new());
//! signer.init(&private_key)?;
//! signer.update(b"hello")?;
//! let mut signature = vec![0; signer.max_signature_size()];
//! let length = signer.generate_signature(&mut signature)?;
//!
//! // 驗章：收到別人的公鑰時先檢查，再以同一個雜湊驗證。
//! public_key.validate()?;
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
mod gost3410_error;
mod group_generator;
mod key_pair_generator;
mod math;
pub mod named_domains;
mod params;
mod signer;

pub use error::Gost3410SignerError;
pub use gost3410_error::Gost3410Error;
pub use group_generator::Gost3410GroupGenerator;
pub use key_pair_generator::Gost3410KeyPairGenerator;
pub use params::{
    Gost3410KeyGenerationParams, Gost3410Parameters, Gost3410PrivateKey, Gost3410PublicKey,
    Gost3410ValidationParameters,
};
pub use signer::Gost3410Signer;
