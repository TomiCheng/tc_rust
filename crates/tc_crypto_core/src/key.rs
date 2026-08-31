//! Key-bearing parameter abstraction.

/// Parameters that provide cryptographic key material.
pub trait Key {
    /// Returns the key bytes.
    fn key(&self) -> &[u8];
}
