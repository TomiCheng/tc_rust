//! DSA 的參數與金鑰層，移植自 Bouncy Castle：參數、驗證參數、公私鑰、金鑰對產生器，以及
//! FIPS 186-2 與 186-3 的參數產生器。簽章在 `tc_dsa_signer`。

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
