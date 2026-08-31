//! Ascon-AEAD128 initialization-parameter contract.

use super::{KEY_BYTES, NONCE_BYTES};

/// Key, nonce, and optional initial AAD used to initialize Ascon-AEAD128.
///
/// Implementations may borrow or own the parameter data. The fixed-size key
/// and nonce return types ensure that every implementation supplies the sizes
/// required by Ascon-AEAD128.
pub trait Params {
    /// Returns the 16-byte secret key.
    fn key(&self) -> &[u8; KEY_BYTES];

    /// Returns the 16-byte nonce.
    fn nonce(&self) -> &[u8; NONCE_BYTES];

    /// Returns the initial associated data, which may be empty.
    fn initial_aad(&self) -> &[u8];
}
