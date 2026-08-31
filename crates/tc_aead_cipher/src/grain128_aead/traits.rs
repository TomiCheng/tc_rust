//! Grain-128AEAD initialization-parameter contract.

use super::{KEY_BYTES, NONCE_BYTES};

/// Key, nonce, and AAD information used to initialize Grain-128AEAD.
///
/// Grain-128AEAD authenticates an encoding of the total AAD length before the
/// AAD itself. Supplying that length at initialization allows the engine to
/// process AAD incrementally without buffering it or requiring allocation.
pub trait Params {
    /// Returns the 16-byte secret key.
    fn key(&self) -> &[u8; KEY_BYTES];

    /// Returns the 12-byte public nonce.
    fn nonce(&self) -> &[u8; NONCE_BYTES];

    /// Returns the declared total AAD length in bytes.
    fn aad_len(&self) -> usize;

    /// Returns AAD supplied during initialization, which may be empty.
    fn initial_aad(&self) -> &[u8];
}
