//! Legacy Ascon initialization-parameter contract.

use super::NONCE_BYTES;

/// Key, nonce, and optional initial AAD used to initialize a legacy Ascon
/// variant.
///
/// Implementations may borrow or own their parameter data. The selected
/// [`super::Variant`] validates the key length during engine initialization.
pub trait Params {
    /// Returns the secret key.
    fn key(&self) -> &[u8];

    /// Returns the 16-byte nonce.
    fn nonce(&self) -> &[u8; NONCE_BYTES];

    /// Returns the initial associated data, which may be empty.
    fn initial_aad(&self) -> &[u8];
}
