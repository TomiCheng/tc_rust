//! Poly1305 initialization-parameter contract.

use super::KEY_BYTES;

/// One-time key used to initialize raw Poly1305 without a block cipher.
///
/// Implementations may borrow or own the key. The fixed-size return type
/// ensures that every implementation supplies the 32 bytes required by
/// Poly1305.
pub trait Params {
    /// Returns the 32-byte one-time key.
    fn key(&self) -> &[u8; KEY_BYTES];
}
