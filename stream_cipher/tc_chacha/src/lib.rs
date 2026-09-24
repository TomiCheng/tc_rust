//! ChaCha, IETF ChaCha20 (RFC 8439) and XChaCha20 stream ciphers.

#![no_std]

#[cfg(feature = "rustcrypto")]
mod rustcrypto_engine;

#[cfg(feature = "rustcrypto")]
pub use rustcrypto_engine::{
    ChaCha7539RustCryptoEngine, ChaChaRustCryptoEngine, XChaCha20RustCryptoEngine,
};
