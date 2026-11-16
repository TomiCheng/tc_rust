//! Diffie-Hellman 的網域參數與金鑰，移植自 Bouncy Castle 的 `DHParameters`、
//! `DHPublicKeyParameters`、`DHPrivateKeyParameters`、`DHKeyPairGenerator` 與
//! `DHParametersGenerator`。DH 協商與 ElGamal 共用這一層。[`standard_groups`] 是 BC 的
//! `DHStandardGroups`：RFC 2409、3526、7919 公布的群組。
//!
//! ```no_run
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_dh_key::{
//!     DhGroupGenerationParams, DhGroupGenerator, DhKeyGenerationParams, DhKeyPairGenerator,
//! };
//!
//! // 產生 2048 位元的安全質數 p = 2q + 1，g 固定為 2；很慢，可能要數十秒到數分鐘。
//! let group_params = DhGroupGenerationParams::new();
//! let mut group_generator = DhGroupGenerator::new(rand::rng());
//! group_generator.init(&group_params)?;
//! let group = group_generator.generate_group()?;
//!
//! // 依群組產生金鑰對：y 交給對方，x 留在這裡，drop 時清除。
//! let params = DhKeyGenerationParams::new(group);
//! let mut generator = DhKeyPairGenerator::new(rand::rng());
//! generator.init(&params)?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//! public_key.validate()?;
//! # Ok::<(), tc_dh_key::DhError>(())
//! ```

#![no_std]

extern crate alloc;

mod error;
mod group_generator;
mod key_pair_generator;
mod math;
mod params;
mod small_primes;
pub mod standard_groups;

pub use error::DhError;
pub use group_generator::DhGroupGenerator;
pub use key_pair_generator::DhKeyPairGenerator;
pub use params::{
    DhGroupGenerationParams, DhKeyGenerationParams, DhParameters, DhPrivateKey, DhPublicKey,
    DhValidationParameters,
};
