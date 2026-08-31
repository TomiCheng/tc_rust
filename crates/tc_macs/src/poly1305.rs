//! Poly1305 message authentication code.

mod engine;
mod params;
mod traits;

pub use engine::{Engine, Error};
pub use params::BorrowedParams;
pub use traits::Params;

/// Poly1305 input block length in bytes.
pub const BLOCK_BYTES: usize = 16;

/// Poly1305 one-time key length in bytes.
pub const KEY_BYTES: usize = 32;

/// Poly1305 authentication-tag length in bytes.
pub const TAG_BYTES: usize = 16;
