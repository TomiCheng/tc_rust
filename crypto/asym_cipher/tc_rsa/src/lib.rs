#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
mod params;
#[cfg(feature = "alloc")]
mod rsa_key_pair_generator;
mod traits;

pub use error::RsaError;
#[cfg(feature = "alloc")]
pub use params::RsaKeyGenerationParams;
pub use params::RsaKeyOwned;
pub use params::RsaPrivateCrtKeyOwned;
#[cfg(feature = "alloc")]
pub use rsa_key_pair_generator::RsaKeyPairGenerator;
pub use traits::RsaKeyParams;
pub use traits::RsaPrivateCrtKeyParams;
