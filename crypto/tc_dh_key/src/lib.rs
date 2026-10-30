//! Diffie-Hellman 的網域參數與金鑰，移植自 Bouncy Castle 的 `DHParameters`、
//! `DHPublicKeyParameters`、`DHPrivateKeyParameters`、`DHKeyPairGenerator` 與
//! `DHParametersGenerator`。DH 協商與 ElGamal 共用這一層。
//!
//! ```
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_dh_key::{DhKeyGenerationParams, DhKeyPairGenerator, DhParametersGenerator};
//!
//! let mut rng = rand::rng();
//!
//! // 產生安全質數 p = 2q + 1，g 固定為 2；真實用途要 2048 位元以上。
//! let mut parameters_generator = DhParametersGenerator::new();
//! parameters_generator.init(256, 20, &mut rng)?;
//! let params = parameters_generator.generate_parameters()?;
//!
//! // 依參數產生金鑰對：y 交給對方，x 留在這裡，drop 時清除。
//! let mut generator = DhKeyPairGenerator::new();
//! generator.init(DhKeyGenerationParams::new(params, &mut rng))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//! public_key.validate()?;
//! # Ok::<(), tc_dh_key::DhError>(())
//! ```

#![no_std]

extern crate alloc;

mod error;
mod key_pair_generator;
mod math;
mod parameters_generator;
mod params;
mod small_primes;

pub use error::DhError;
pub use key_pair_generator::DhKeyPairGenerator;
pub use parameters_generator::DhParametersGenerator;
pub use params::{
    DhKeyGenerationParams, DhParameters, DhPrivateKey, DhPublicKey, DhValidationParameters,
};
