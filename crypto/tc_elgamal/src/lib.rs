//! ElGamal 加密，移植自 Bouncy Castle 的 `ElGamalEngine`、`ElGamalParameters`、
//! `ElGamalPublicKeyParameters`、`ElGamalPrivateKeyParameters` 與其產生器。金鑰與參數的
//! 產生交給 `tc_dh_key`，同 BC 借用 DH 的產生器。
//!
//! 引擎實作 `tc_asym_cipher` 的非對稱加密 trait，區塊大小與 `tc_rsa` 一致，可以直接套上
//! PKCS#1 或 OAEP。
//!
//! ```no_run
//! use tc_asym_cipher::{
//!     AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
//!     KeyPairGeneratorInit,
//! };
//! use tc_dh_key::DhGroupGenerationParams;
//! use tc_elgamal::{
//!     ElGamalEngine, ElGamalKeyGenerationParams, ElGamalKeyPairGenerator,
//!     ElGamalGroupGenerator,
//! };
//!
//! // 參數：2048 位元的安全質數 p 與 g = 2；很慢，可能要數十秒到數分鐘。
//! let mut group_generator = ElGamalGroupGenerator::new(rand::rng());
//! group_generator.init(&DhGroupGenerationParams::new())?;
//! let params = group_generator.generate_group()?;
//!
//! // 收件人的金鑰對。
//! let mut generator = ElGamalKeyPairGenerator::new(rand::rng());
//! generator.init(&ElGamalKeyGenerationParams::new(params))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! // 寄件人以公鑰加密，收件人以私鑰解密。
//! let mut encryptor = ElGamalEngine::new(rand::rng());
//! encryptor.init(CipherDirection::Encrypt, &public_key)?;
//! let mut ciphertext = vec![0; encryptor.output_block_size()];
//! encryptor.process_block(b"hello", &mut ciphertext)?;
//!
//! let mut decryptor = ElGamalEngine::new(rand::rng());
//! decryptor.init(CipherDirection::Decrypt, &private_key)?;
//! let mut plaintext = vec![0; decryptor.output_block_size()];
//! let length = decryptor.process_block(&ciphertext, &mut plaintext)?;
//! assert!(plaintext[..length].ends_with(b"hello"));
//! # Ok::<(), tc_elgamal::ElGamalError>(())
//! ```

#![no_std]

extern crate alloc;

mod engine;
mod error;
mod group_generator;
mod key_pair_generator;
mod params;

pub use engine::ElGamalEngine;
pub use error::ElGamalError;
pub use group_generator::ElGamalGroupGenerator;
pub use key_pair_generator::ElGamalKeyPairGenerator;
pub use params::{
    ElGamalKeyGenerationParams, ElGamalParameters, ElGamalPrivateKey, ElGamalPublicKey,
};
