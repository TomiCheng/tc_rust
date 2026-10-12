#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
mod params;
mod rsa_core_engine;
#[cfg(feature = "alloc")]
mod rsa_key_pair_generator;
mod traits;

pub use error::RsaError;
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
