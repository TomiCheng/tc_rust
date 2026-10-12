//! The key of an RSA operation.

/// A key an RSA operation runs with: a modulus and one exponent, as
/// integers of type `T`.
///
/// Nothing here promises the values make a valid RSA key: the operation
/// that takes the key calls [`validate`](Self::validate) when it is
/// initialized.
pub trait RsaKeyParams<T> {
    /// Whether the exponent is private. Constant time.
    fn is_private_key(&self) -> bool;

    /// The modulus `n`. Constant time.
    fn modulus(&self) -> &T;

    /// The exponent: `e` for a public key, `d` for a private one. Constant
    /// time.
    fn exponent(&self) -> &T;

    /// Whether the key passes its checks, as Bouncy Castle's
    /// `RsaKeyParameters` checks one when it is built. An operation calls it
    /// when it is initialized, and fails with `RsaError::InvalidKey` unless
    /// it passes; a `bool` leaves what to check, and why a key fails, to
    /// each implementation. The keys of
    /// this crate check an odd modulus of at most 16384 bits, with no prime
    /// factor below 212, proved composite by Miller-Rabin, and an exponent
    /// that is not zero, and odd for a public key, as Bouncy Castle does;
    /// they remember that they passed, so that a second call does nothing,
    /// and the keys this crate generates start out passed. Each
    /// implementation states its timing; for a public modulus, it may be
    /// variable time.
    fn validate(&self) -> bool;
}
