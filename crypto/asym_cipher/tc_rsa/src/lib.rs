#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod block;
mod error;
mod fixed_rsa_crt_core_engine;
#[cfg(feature = "alloc")]
mod padded_rsa_crt_core_engine;
mod params;
mod rsa_core_engine;
#[cfg(feature = "alloc")]
mod rsa_key_pair_generator;
#[cfg(test)]
mod testing;
mod traits;
mod validation;

pub use error::RsaError;
pub use fixed_rsa_crt_core_engine::FixedRsaCrtCoreEngine;
#[cfg(feature = "alloc")]
pub use padded_rsa_crt_core_engine::PaddedRsaCrtCoreEngine;
#[cfg(feature = "alloc")]
pub use params::RsaKeyGenerationParamsOwned;
#[cfg(feature = "alloc")]
pub use params::RsaKeyGenerationParamsRef;
pub use params::RsaKeyOwned;
pub use params::RsaPrivateCrtKeyOwned;
pub use rsa_core_engine::RsaCoreEngine;
#[cfg(feature = "alloc")]
pub use rsa_key_pair_generator::RsaKeyPairGenerator;
#[cfg(feature = "alloc")]
pub use traits::RsaKeyGenerationParams;
pub use traits::RsaKeyParams;
pub use traits::RsaPrivateCrtKeyParams;
