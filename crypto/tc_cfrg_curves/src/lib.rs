//! CFRG 曲線：RFC 7748 的 X25519、X448 金鑰協商與 RFC 8032 的 Ed25519、Ed448 簽章，
//! 移植自 Bouncy Castle C#。

#![no_std]

#[cfg(any(feature = "ed25519", feature = "ed448"))]
extern crate alloc;

#[cfg(feature = "ed25519")]
mod ed25519;
#[cfg(feature = "ed448")]
mod ed448;
mod error;
#[cfg(any(
    feature = "x25519",
    feature = "x448",
    feature = "ed25519",
    feature = "ed448"
))]
mod key_generation_params;
#[cfg(feature = "x25519")]
mod x25519;
#[cfg(feature = "x448")]
mod x448;

#[cfg(feature = "ed448")]
pub use ed448::{
    Ed448KeyPairGenerator, Ed448PhSigner, Ed448PrivateKey, Ed448PublicKey, Ed448Signer,
};
#[cfg(feature = "ed25519")]
pub use ed25519::{
    Ed25519CtxSigner, Ed25519KeyPairGenerator, Ed25519PhSigner, Ed25519PrivateKey,
    Ed25519PublicKey, Ed25519Signer,
};
pub use error::CfrgError;
#[cfg(any(
    feature = "x25519",
    feature = "x448",
    feature = "ed25519",
    feature = "ed448"
))]
pub use key_generation_params::KeyGenerationParams;
#[cfg(feature = "x448")]
pub use x448::{X448Agreement, X448KeyPairGenerator, X448PrivateKey, X448PublicKey};
#[cfg(feature = "x25519")]
pub use x25519::{X25519Agreement, X25519KeyPairGenerator, X25519PrivateKey, X25519PublicKey};
