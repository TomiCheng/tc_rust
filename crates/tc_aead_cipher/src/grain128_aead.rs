//! Grain-128AEAD authenticated encryption.

mod engine;
mod params;
mod traits;

pub use engine::Engine;
pub use params::BorrowedParams;
#[cfg(feature = "alloc")]
pub use params::OwnedParams;
pub use traits::Params;

/// Grain-128AEAD key length in bytes.
pub const KEY_BYTES: usize = 16;

/// Grain-128AEAD nonce length in bytes.
pub const NONCE_BYTES: usize = 12;

/// Grain-128AEAD authentication-tag length in bytes.
pub const TAG_BYTES: usize = 8;
