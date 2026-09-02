//! Finalized Ascon-AEAD128 from NIST SP 800-232.

mod engine;
mod params;

pub use engine::Engine;
pub use params::Params;

/// Secret-key length in bytes.
pub const KEY_BYTES: usize = 16;
/// Nonce length in bytes.
pub const NONCE_BYTES: usize = 16;
/// Authentication-tag length in bytes.
pub const TAG_BYTES: usize = 16;
