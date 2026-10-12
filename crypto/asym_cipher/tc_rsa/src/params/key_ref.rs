//! An RSA key borrowed from the caller.

use core::sync::atomic::{AtomicBool, Ordering};

use num_traits::Zero;
use tc_bigint::BitOps;
use tc_prime::Primality;

use crate::RsaKeyParams;
use crate::validation::key_passes;

/// An RSA key borrowed from the caller: a modulus and one exponent, as
/// integers of type `T` that live for `'a`. It is a view only: nothing is
/// checked when it is built, and the operation that takes it calls
/// [`validate`](RsaKeyParams::validate) when it is initialized, which
/// checks the key once and remembers that it passed. The integers are the
/// caller's, and so are theirs to wipe; there is no `Debug`, which would
/// show the exponent of a private key.
pub struct RsaKeyRef<'a, T> {
    is_private: bool,
    modulus: &'a T,
    exponent: &'a T,
    /// Whether the key passed [`validate`](RsaKeyParams::validate), so that
    /// a second call does nothing.
    validated: AtomicBool,
}

impl<'a, T> RsaKeyRef<'a, T> {
    /// The key of `modulus` and `exponent`, which is `e` for a public key
    /// and `d` for a private one. Constant time.
    pub const fn new(is_private: bool, modulus: &'a T, exponent: &'a T) -> Self {
        Self {
            is_private,
            modulus,
            exponent,
            validated: AtomicBool::new(false),
        }
    }
}

/// A copy of the view that remembers whether the key passed. Constant time.
impl<T> Clone for RsaKeyRef<'_, T> {
    fn clone(&self) -> Self {
        Self {
            is_private: self.is_private,
            modulus: self.modulus,
            exponent: self.exponent,
            validated: AtomicBool::new(self.validated.load(Ordering::Relaxed)),
        }
    }
}

/// The borrowed values, and the check of [`RsaKeyParams`], once: a key that
/// passed is not checked again. Constant time, but for `validate`, which is
/// variable time: only for public values, as the modulus is.
impl<T> RsaKeyParams<T> for RsaKeyRef<'_, T>
where
    T: Zero + BitOps + Primality + From<u8>,
{
    fn is_private_key(&self) -> bool {
        self.is_private
    }

    fn modulus(&self) -> &T {
        self.modulus
    }

    fn exponent(&self) -> &T {
        self.exponent
    }

    fn validate(&self) -> bool {
        if self.validated.load(Ordering::Relaxed) {
            return true;
        }
        let passes = key_passes(self.is_private, self.modulus, self.exponent);
        self.validated.store(passes, Ordering::Relaxed);
        passes
    }
}

#[cfg(test)]
mod tests {
    use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
    use tc_bigint::FixedBigUint;

    use super::RsaKeyRef;
    use crate::{FixedRsaCoreEngine, RsaKeyParams};

    #[test]
    fn a_borrowed_key_runs_as_an_owned_one_does() {
        let (n, e, d) = (
            FixedBigUint::<1>::from(1_022_117u32),
            FixedBigUint::<1>::from(17u32),
            FixedBigUint::<1>::from(180_017u32),
        );
        let mut engine = FixedRsaCoreEngine::new();
        engine
            .init(CipherDirection::Encrypt, &RsaKeyRef::new(false, &n, &e))
            .unwrap();
        let mut ciphertext = [0; 3];
        engine.process_block(&[65], &mut ciphertext).unwrap();
        assert_eq!(ciphertext, [0x02, 0xb3, 0xcd]);
        engine
            .init(CipherDirection::Decrypt, &RsaKeyRef::new(true, &n, &d))
            .unwrap();
        let mut plaintext = [0; 3];
        engine.process_block(&ciphertext, &mut plaintext).unwrap();
        assert_eq!(plaintext, [0, 0, 65]);
    }

    #[test]
    fn a_borrowed_key_is_checked_once_and_its_copy_remembers() {
        let (n, e) = (
            FixedBigUint::<1>::from(1_022_117u32),
            FixedBigUint::<1>::from(17u32),
        );
        let key = RsaKeyRef::new(false, &n, &e);
        assert!(key.validate());
        assert!(
            key.clone()
                .validated
                .load(core::sync::atomic::Ordering::Relaxed)
        );
        let bad = FixedBigUint::<1>::from(3233u32);
        assert!(!RsaKeyRef::new(false, &bad, &e).validate());
    }
}
