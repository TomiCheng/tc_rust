//! The private key of an RSA operation, with its CRT values.

use super::RsaKeyParams;

/// A private key with the values of the Chinese Remainder Theorem: the
/// primes, and the values modulo them, as integers of type `H`, so that a
/// fixed-width key can hold them at half its width.
///
/// It extends [`RsaKeyParams`], whose exponent is `d`. As there, nothing
/// here promises the values are valid.
pub trait RsaPrivateCrtKeyParams<T, H = T>: RsaKeyParams<T> {
    /// The public exponent `e`. Constant time.
    fn public_exponent(&self) -> &T;

    /// The prime `p`. Constant time.
    fn p(&self) -> &H;

    /// The prime `q`. Constant time.
    fn q(&self) -> &H;

    /// `d mod (p - 1)`. Constant time.
    fn dp(&self) -> &H;

    /// `d mod (q - 1)`. Constant time.
    fn dq(&self) -> &H;

    /// `q⁻¹ mod p`. Constant time.
    fn q_inv(&self) -> &H;
}
