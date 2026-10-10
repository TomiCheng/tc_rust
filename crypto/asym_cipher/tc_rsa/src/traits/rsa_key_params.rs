//! The key of an RSA operation.

/// A key an RSA operation runs with: a modulus and one exponent, as
/// integers of type `T`.
///
/// Nothing here promises the values make a valid RSA key: the operation
/// that takes the key checks it when it is initialized.
pub trait RsaKeyParams<T> {
    /// Whether the exponent is private. Constant time.
    fn is_private_key(&self) -> bool;

    /// The modulus `n`. Constant time.
    fn modulus(&self) -> &T;

    /// The exponent: `e` for a public key, `d` for a private one. Constant
    /// time.
    fn exponent(&self) -> &T;
}
