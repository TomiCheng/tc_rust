#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod block;
mod core_engine;
mod crt_engine;
mod error;
#[cfg(feature = "alloc")]
mod key_pair_generator;
mod params;
#[cfg(test)]
mod testing;
mod traits;
mod validation;

pub use core_engine::FixedRsaCoreEngine;
#[cfg(feature = "alloc")]
pub use core_engine::PaddedRsaCoreEngine;
pub use crt_engine::FixedRsaCrtCoreEngine;
#[cfg(feature = "alloc")]
pub use crt_engine::PaddedRsaCrtCoreEngine;
pub use error::RsaError;
#[cfg(feature = "alloc")]
pub use key_pair_generator::RsaKeyPairGenerator;
#[cfg(feature = "rustcrypto")]
pub use key_pair_generator::RsaKeyPairGeneratorRustCrypto;
#[cfg(feature = "alloc")]
pub use params::RsaKeyGenerationParamsOwned;
#[cfg(feature = "alloc")]
pub use params::RsaKeyGenerationParamsRef;
pub use params::RsaKeyOwned;
pub use params::RsaKeyRef;
#[cfg(feature = "rustcrypto")]
pub use params::RsaKeyRustCrypto;
pub use params::RsaPrivateCrtKeyOwned;
pub use params::RsaPrivateCrtKeyRef;
#[cfg(feature = "rustcrypto")]
pub use params::RsaPrivateCrtKeyRustCrypto;
#[cfg(feature = "alloc")]
pub use traits::RsaKeyGenerationParams;
pub use traits::RsaKeyParams;
pub use traits::RsaPrivateCrtKeyParams;
