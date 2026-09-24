//! ChaCha, IETF ChaCha20 (RFC 8439) and XChaCha20 stream ciphers.

#![no_std]

mod chacha;
mod chacha7539_portable_engine;
mod chacha_portable_engine;
mod engine;
#[cfg(feature = "rustcrypto")]
mod rustcrypto_engine;
mod xchacha20_portable_engine;

pub use chacha_portable_engine::ChaChaPortableEngine;
pub use chacha7539_portable_engine::ChaCha7539PortableEngine;
pub use engine::{ChaCha7539Engine, ChaChaEngine, XChaCha20Engine};
#[cfg(feature = "rustcrypto")]
pub use rustcrypto_engine::{
    ChaCha7539RustCryptoEngine, ChaChaRustCryptoEngine, XChaCha20RustCryptoEngine,
};
pub use xchacha20_portable_engine::XChaCha20PortableEngine;

/// Round count of ChaCha20, used unless
/// [`ChaChaEngine::with_rounds`] picks another.
pub const DEFAULT_ROUNDS: usize = 20;
/// Keystream block length in bytes.
pub const BLOCK_BYTES: usize = 64;
