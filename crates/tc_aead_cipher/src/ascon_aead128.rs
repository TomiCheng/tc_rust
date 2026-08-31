//! Ascon-AEAD128 types and constants.

mod engine;
mod params;

pub use engine::AsconAead128Engine;
pub use params::AsconAead128Params;

/// Ascon-AEAD128 key length in bytes.
pub const ASCON_AEAD128_KEY_BYTES: usize = 16;

/// Ascon-AEAD128 nonce length in bytes.
pub const ASCON_AEAD128_NONCE_BYTES: usize = 16;

/// Ascon-AEAD128 authentication-tag length in bytes.
pub const ASCON_AEAD128_TAG_BYTES: usize = 16;
