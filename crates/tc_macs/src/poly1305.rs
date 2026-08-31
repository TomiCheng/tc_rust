//! Poly1305 message authentication code.

mod engine;
mod params;
mod traits;

pub use engine::{CipherEngine, CipherError, Engine, Error};
pub use params::{BorrowedParams, CipherParams};
pub use traits::Params;

/// Poly1305 input block length in bytes.
pub const BLOCK_BYTES: usize = 16;

/// Key length required by Poly1305's optional block cipher.
pub const CIPHER_KEY_BYTES: usize = 16;

/// Poly1305 one-time key length in bytes.
pub const KEY_BYTES: usize = 32;

/// Nonce length required by Poly1305's optional block-cipher form.
pub const NONCE_BYTES: usize = 16;

/// Poly1305 authentication-tag length in bytes.
pub const TAG_BYTES: usize = 16;
