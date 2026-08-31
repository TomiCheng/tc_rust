//! SCHWAEMM initialization-parameter contract.

/// Key, nonce, and optional initial AAD used to initialize SCHWAEMM.
///
/// Implementations may borrow or own their data. The selected engine variant
/// validates the exact key and nonce lengths during initialization.
pub trait Params {
    /// Returns the secret key.
    fn key(&self) -> &[u8];

    /// Returns the public nonce.
    fn nonce(&self) -> &[u8];

    /// Returns the initial associated data, which may be empty.
    fn initial_aad(&self) -> &[u8];
}
