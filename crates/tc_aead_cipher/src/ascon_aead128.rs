//! Ascon-AEAD128 types and constants.

mod engine;
mod params;
mod traits;

pub use engine::Engine;
pub use params::BorrowedParams;
#[cfg(feature = "alloc")]
pub use params::OwnedParams;
pub use traits::Params;

/// Ascon-AEAD128 key length in bytes.
pub const KEY_BYTES: usize = 16;

/// Ascon-AEAD128 nonce length in bytes.
pub const NONCE_BYTES: usize = 16;

/// Ascon-AEAD128 authentication-tag length in bytes.
pub const TAG_BYTES: usize = 16;
