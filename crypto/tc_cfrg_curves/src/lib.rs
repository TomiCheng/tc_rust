//! CFRG 曲線：RFC 7748 的 X25519、X448 金鑰協商與 RFC 8032 的 Ed25519、Ed448 簽章，
//! 移植自 Bouncy Castle C#。

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod agreement;
mod edwards;
mod error;
mod generator;
mod params;
mod rfc7748;
mod signer;

#[cfg(feature = "x448")]
pub use agreement::X448Agreement;
pub use agreement::X25519Agreement;
pub use error::CfrgError;
#[cfg(feature = "ed448")]
pub use generator::Ed448KeyPairGenerator;
#[cfg(feature = "x448")]
pub use generator::X448KeyPairGenerator;
pub use generator::{Ed25519KeyPairGenerator, X25519KeyPairGenerator};
#[cfg(feature = "ed448")]
pub use params::{Ed448PrivateKey, Ed448PublicKey};
pub use params::{
    Ed25519PrivateKey, Ed25519PublicKey, KeyGenerationParams, X25519PrivateKey, X25519PublicKey,
};
#[cfg(feature = "x448")]
pub use params::{X448PrivateKey, X448PublicKey};
#[cfg(feature = "ed448")]
pub use signer::{Ed448PhSigner, Ed448Signer};
pub use signer::{Ed25519CtxSigner, Ed25519PhSigner, Ed25519Signer};
