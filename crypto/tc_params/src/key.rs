//! Key parameter abstraction.

/// Parameters that provide cryptographic key material.
pub trait KeyParams {
    /// Returns the key bytes.
    fn key(&self) -> &[u8];
}
