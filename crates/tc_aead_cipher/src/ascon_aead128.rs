//! Ascon-AEAD128 types and constants.

mod engine;
mod params;
mod r#trait;

pub use engine::Engine;
pub use params::BorrowedParams;
pub use r#trait::Params;

/// Ascon-AEAD128 key length in bytes.
pub const KEY_BYTES: usize = 16;

/// Ascon-AEAD128 nonce length in bytes.
pub const NONCE_BYTES: usize = 16;

/// Ascon-AEAD128 authentication-tag length in bytes.
pub const TAG_BYTES: usize = 16;
