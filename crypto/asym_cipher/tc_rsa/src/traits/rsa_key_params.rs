//! The key of an RSA operation.

use num_traits::Zero;
use tc_bigint::BitOps;
use tc_prime::Primality;

use crate::RsaError;
use crate::validation::validate_key;

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

    /// Checks the key as Bouncy Castle's `RsaKeyParameters` does when it is
    /// built: a modulus that is odd, of at most 16384 bits, with no prime
    /// factor below 212, and proved composite by Miller-Rabin, and an
    /// exponent that is not zero, and odd for a public key. An operation
    /// calls it when it is initialized. An implementation may remember that
    /// its key passed, so that a second call does nothing, as those of this
    /// crate do, and the keys this crate generates start out passed; this
    /// one checks every time. Variable time: only for public values, as the
    /// modulus is; the exponent is only read for zero and its parity.
    fn validate(&self) -> Result<(), RsaError>
    where
        T: Zero + BitOps + Primality + From<u8>,
    {
        validate_key(self.is_private_key(), self.modulus(), self.exponent())
    }
}
