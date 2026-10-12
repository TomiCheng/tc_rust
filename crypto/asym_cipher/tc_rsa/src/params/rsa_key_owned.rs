//! An RSA key held by value.

use core::sync::atomic::{AtomicBool, Ordering};

use num_traits::Zero;
use tc_bigint::BitOps;
use tc_prime::Primality;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

use crate::validation::validate_key;
use crate::{RsaError, RsaKeyParams};

/// An RSA key held by value: a modulus and one exponent, as integers of
/// type `T`. It is a container only: nothing is checked when it is built,
/// and the operation that takes it calls
/// [`validate`](RsaKeyParams::validate) when it is initialized, which
/// checks the key once and remembers that it passed; the keys this crate
/// generates start out passed. Both integers are wiped on drop; there is no
/// `Debug`, which would show the exponent of a private key.
pub struct RsaKeyOwned<T: Zeroize> {
    is_private: bool,
    modulus: T,
    exponent: T,
    /// Whether the key passed [`validate`](RsaKeyParams::validate), so that
    /// a second call does nothing.
    validated: AtomicBool,
}

impl<T: Zeroize> RsaKeyOwned<T> {
    /// The key of `modulus` and `exponent`, which is `e` for a public key
    /// and `d` for a private one. Constant time.
    pub const fn new(is_private: bool, modulus: T, exponent: T) -> Self {
        Self {
            is_private,
            modulus,
            exponent,
            validated: AtomicBool::new(false),
        }
    }

    /// The key marked as passed, for the keys this crate generates.
    /// Constant time.
    #[cfg(any(feature = "alloc", test))]
    pub(crate) fn into_validated(mut self) -> Self {
        *self.validated.get_mut() = true;
        self
    }
}

/// A copy that remembers whether the key passed. Constant time, as the
/// `Clone` of `T` is.
impl<T: Zeroize + Clone> Clone for RsaKeyOwned<T> {
    fn clone(&self) -> Self {
        Self {
            is_private: self.is_private,
            modulus: self.modulus.clone(),
            exponent: self.exponent.clone(),
            validated: AtomicBool::new(self.validated.load(Ordering::Relaxed)),
        }
    }
}

/// The fields as they are held, and the check of [`RsaKeyParams`], once:
/// a key that passed is not checked again. Constant time, but for
/// `validate`, which is variable time: only for public values, as the
/// modulus is.
impl<T: Zeroize> RsaKeyParams<T> for RsaKeyOwned<T> {
    fn is_private_key(&self) -> bool {
        self.is_private
    }

    fn modulus(&self) -> &T {
        &self.modulus
    }

    fn exponent(&self) -> &T {
        &self.exponent
    }

    fn validate(&self) -> Result<(), RsaError>
    where
        T: Zero + BitOps + Primality + From<u8>,
    {
        if self.validated.load(Ordering::Relaxed) {
            return Ok(());
        }
        validate_key(self.is_private, &self.modulus, &self.exponent)?;
        self.validated.store(true, Ordering::Relaxed);
        Ok(())
    }
}

/// Wipes the modulus and the exponent. Constant time, as the `Zeroize` of
/// `T` is.
impl<T: Zeroize> Drop for RsaKeyOwned<T> {
    fn drop(&mut self) {
        self.modulus.zeroize();
        self.exponent.zeroize();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for RsaKeyOwned<T> {}

#[cfg(test)]
mod tests {
    use core::sync::atomic::Ordering;

    use tc_bigint::FixedBigUint;

    use super::RsaKeyOwned;
    use crate::{RsaError, RsaKeyParams};

    fn key(modulus: u32) -> RsaKeyOwned<FixedBigUint<1>> {
        RsaKeyOwned::new(
            false,
            FixedBigUint::from(modulus),
            FixedBigUint::from(17u32),
        )
    }

    #[test]
    fn a_key_that_passes_is_not_checked_again() {
        let key = key(1009 * 1013);
        assert!(!key.validated.load(Ordering::Relaxed));
        assert_eq!(key.validate(), Ok(()));
        assert!(key.validated.load(Ordering::Relaxed));
        assert_eq!(key.validate(), Ok(()));
        assert!(key.clone().validated.load(Ordering::Relaxed));
    }

    #[test]
    fn a_key_that_fails_is_checked_again_and_fails_again() {
        let key = key(3233);
        assert_eq!(key.validate(), Err(RsaError::ModulusHasSmallFactor));
        assert!(!key.validated.load(Ordering::Relaxed));
        assert_eq!(key.validate(), Err(RsaError::ModulusHasSmallFactor));
    }

    #[test]
    fn a_key_marked_as_passed_is_not_checked() {
        assert_eq!(key(3233).into_validated().validate(), Ok(()));
    }
}
