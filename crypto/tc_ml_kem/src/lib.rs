//! ML-KEM（FIPS 203）金鑰封裝機制，移植自 Bouncy Castle：三組參數、金鑰與產生器，以及實作
//! `tc_kem` 的封裝方與解封裝方。純軟體實作；雜湊用 `tc_keccak` 的 SHA3 與 SHAKE。
//!
//! ```
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_kem::{KemDecapsulator, KemEncapsulator, KemInit};
//! use tc_ml_kem::{
//!     MlKemDecapsulator, MlKemEncapsulator, MlKemKeyGenerationParams, MlKemKeyPairGenerator,
//!     MlKemParameters,
//! };
//!
//! // 收件人產生金鑰對，公開封裝金鑰。
//! let params = MlKemParameters::ML_KEM_768;
//! let mut rng = rand::rng();
//! let mut generator = MlKemKeyPairGenerator::new();
//! generator.init(MlKemKeyGenerationParams::new(params, &mut rng))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! // 寄件人以公鑰封裝，得到要寄出的密文與自己的共享秘密。
//! let mut sender = MlKemEncapsulator::new(params, rand::rng());
//! sender.init(&public_key)?;
//! let mut ciphertext = vec![0; sender.encapsulation_length()];
//! let mut sender_secret = [0; 32];
//! sender.encapsulate(&mut ciphertext, &mut sender_secret)?;
//!
//! // 收件人以私鑰解封裝，取回同一個秘密。
//! let mut receiver = MlKemDecapsulator::new(params);
//! receiver.init(&private_key)?;
//! let mut receiver_secret = [0; 32];
//! receiver.decapsulate(&ciphertext, &mut receiver_secret)?;
//! assert_eq!(sender_secret, receiver_secret);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod cbd;
mod engine;
mod error;
mod indcpa;
mod kem;
mod key_pair_generator;
mod keys;
mod ntt;
mod params;
mod poly;
mod poly_vec;
mod reduce;

pub use error::MlKemError;
pub use kem::{MlKemDecapsulator, MlKemEncapsulator};
pub use key_pair_generator::{MlKemKeyGenerationParams, MlKemKeyPairGenerator};
pub use keys::{MlKemPrivateKey, MlKemPublicKey};
pub use params::MlKemParameters;
