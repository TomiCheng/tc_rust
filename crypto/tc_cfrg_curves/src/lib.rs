//! CFRG 曲線：RFC 7748 的 X25519、X448 金鑰協商與 RFC 8032 的 Ed25519、Ed448 簽章，
//! 移植自 Bouncy Castle C#。

#![no_std]

extern crate alloc;

mod ed25519;
#[cfg(feature = "ed448")]
mod ed448;
mod error;
mod params;
mod x25519;
#[cfg(feature = "x448")]
mod x448;

#[cfg(feature = "ed448")]
pub use ed448::{Ed448KeyPairGenerator, Ed448PhSigner, Ed448Signer};
pub use ed25519::{Ed25519CtxSigner, Ed25519KeyPairGenerator, Ed25519PhSigner, Ed25519Signer};
pub use error::CfrgError;
#[cfg(feature = "ed448")]
pub use params::{Ed448PrivateKey, Ed448PublicKey};
pub use params::{
    Ed25519PrivateKey, Ed25519PublicKey, KeyGenerationParams, X25519PrivateKey, X25519PublicKey,
};
#[cfg(feature = "x448")]
pub use params::{X448PrivateKey, X448PublicKey};
#[cfg(feature = "x448")]
pub use x448::{X448Agreement, X448KeyPairGenerator};
pub use x25519::{X25519Agreement, X25519KeyPairGenerator};
