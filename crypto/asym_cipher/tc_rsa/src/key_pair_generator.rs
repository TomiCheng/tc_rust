//! RSA key pair generation: as Bouncy Castle's `RsaKeyPairGenerator` runs
//! it, and through the RustCrypto `rsa` crate.

mod generation;
mod generator;
#[cfg(feature = "rustcrypto")]
mod rustcrypto;

pub use generator::RsaKeyPairGenerator;
#[cfg(feature = "rustcrypto")]
pub use rustcrypto::RsaKeyPairGeneratorRustCrypto;
