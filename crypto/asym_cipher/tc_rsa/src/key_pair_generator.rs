//! RSA key pair generation: as Bouncy Castle's `RsaKeyPairGenerator` runs
//! it, through the RustCrypto `rsa` crate, and of [`RsaKey`](crate::RsaKey)
//! on whichever of the two the features choose.

mod generation;
mod generator;
mod key_generator;
#[cfg(feature = "rustcrypto")]
mod rustcrypto;

pub use generator::RsaKeyPairGenerator;
pub use key_generator::RsaKeyGenerator;
#[cfg(feature = "rustcrypto")]
pub use rustcrypto::RsaKeyPairGeneratorRustCrypto;
