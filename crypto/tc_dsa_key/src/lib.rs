//! DSA 的參數與金鑰層，移植自 Bouncy Castle：參數、驗證參數、公私鑰、金鑰對產生器，以及
//! FIPS 186-2 與 186-3 的參數產生器。簽章在 `tc_dsa_signer`。
//!
//! ```no_run
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_dsa_key::{
//!     DsaKeyGenerationParams, DsaKeyPairGenerator, DsaParameterGenerationParams,
//!     DsaParametersGenerator,
//! };
//! use tc_sha::Sha256Digest;
//!
//! // 參數：FIPS 186-3 的 L = 2048、N = 256，以 SHA-256 產生；要數秒到數十秒。
//! let mut rng = rand::rng();
//! let mut params_generator = DsaParametersGenerator::with_digest(Sha256Digest::new());
//! params_generator.init_fips186_3(DsaParameterGenerationParams::new(2048, 256, 80, &mut rng))?;
//! let params = params_generator.generate_parameters()?;
//!
//! // 簽章者的金鑰對：x 留在本地、drop 時清除，y 交給驗章者。
//! let mut generator = DsaKeyPairGenerator::new(rand::rng());
//! generator.init(&DsaKeyGenerationParams::new(params))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! // 收到別人的公鑰時先檢查。
//! public_key.validate()?;
//! # Ok::<(), tc_dsa_key::DsaError>(())
//! ```

#![no_std]

extern crate alloc;

mod error;
mod key_pair_generator;
mod math;
mod parameters_generator;
mod params;

pub use error::DsaError;
pub use key_pair_generator::DsaKeyPairGenerator;
pub use parameters_generator::DsaParametersGenerator;
pub use params::{
    DsaKeyGenerationParams, DsaParameterGenerationParams, DsaParameters, DsaPrivateKey,
    DsaPublicKey, DsaValidationParameters,
};
