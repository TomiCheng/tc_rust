//! An RSA private key with its CRT values, held by value.

use core::sync::atomic::{AtomicBool, Ordering};

use num_traits::Zero;
use tc_bigint::BitOps;
use tc_prime::Primality;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};

use crate::validation::validate_key;
use crate::{RsaError, RsaKeyParams, RsaPrivateCrtKeyParams};

/// An RSA private key with the values of the Chinese Remainder Theorem,
/// held by value: the modulus and the exponents as integers of type `T`,
/// the primes and the values modulo them as integers of type `H`, so that
/// a fixed-width key can hold them at half its width. It is a container
/// only: nothing is checked when it is built, and the operation that takes
/// it calls [`validate`](RsaKeyParams::validate) when it is initialized,
/// which checks the key once and remembers that it passed; the keys this
/// crate generates start out passed. Every integer is wiped on drop; there
/// is no `Debug`, which would show them.
pub struct RsaPrivateCrtKeyOwned<T: Zeroize, H: Zeroize = T> {
    modulus: T,
    public_exponent: T,
    private_exponent: T,
    p: H,
    q: H,
    dp: H,
    dq: H,
    q_inv: H,
    /// Whether the key passed [`validate`](RsaKeyParams::validate), so that
    /// a second call does nothing.
    validated: AtomicBool,
}

impl<T: Zeroize, H: Zeroize> RsaPrivateCrtKeyOwned<T, H> {
    /// The key of `modulus`, the exponents `e` and `d`, the primes `p` and
    /// `q`, `d mod (p - 1)`, `d mod (q - 1)` and `q⁻¹ mod p`. Constant
    /// time.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        modulus: T,
        public_exponent: T,
        private_exponent: T,
        p: H,
        q: H,
        dp: H,
        dq: H,
        q_inv: H,
    ) -> Self {
        Self {
            modulus,
            public_exponent,
            private_exponent,
            p,
            q,
            dp,
            dq,
            q_inv,
            validated: AtomicBool::new(false),
        }
    }

    /// The key marked as passed, for the keys this crate generates.
    /// Constant time.
    #[cfg(feature = "alloc")]
    pub(crate) fn into_validated(mut self) -> Self {
        *self.validated.get_mut() = true;
        self
    }
}

/// A copy that remembers whether the key passed. Constant time, as the
/// `Clone` of `T` and `H` is.
impl<T: Zeroize + Clone, H: Zeroize + Clone> Clone for RsaPrivateCrtKeyOwned<T, H> {
    fn clone(&self) -> Self {
        Self {
            modulus: self.modulus.clone(),
            public_exponent: self.public_exponent.clone(),
            private_exponent: self.private_exponent.clone(),
            p: self.p.clone(),
            q: self.q.clone(),
            dp: self.dp.clone(),
            dq: self.dq.clone(),
            q_inv: self.q_inv.clone(),
            validated: AtomicBool::new(self.validated.load(Ordering::Relaxed)),
        }
    }
}

/// A private key, whose exponent is `d`, and the check of
/// [`RsaKeyParams`], once: a key that passed is not checked again.
/// Constant time, but for `validate`, which is variable time: only for
/// public values, as the modulus is.
impl<T: Zeroize, H: Zeroize> RsaKeyParams<T> for RsaPrivateCrtKeyOwned<T, H> {
    fn is_private_key(&self) -> bool {
        true
    }

    fn modulus(&self) -> &T {
        &self.modulus
    }

    fn exponent(&self) -> &T {
        &self.private_exponent
    }

    fn validate(&self) -> Result<(), RsaError>
    where
        T: Zero + BitOps + Primality + From<u8>,
    {
        if self.validated.load(Ordering::Relaxed) {
            return Ok(());
        }
        validate_key(true, &self.modulus, &self.private_exponent)?;
        self.validated.store(true, Ordering::Relaxed);
        Ok(())
    }
}

/// The fields as they are held. Constant time.
impl<T: Zeroize, H: Zeroize> RsaPrivateCrtKeyParams<T, H> for RsaPrivateCrtKeyOwned<T, H> {
    fn public_exponent(&self) -> &T {
        &self.public_exponent
    }

    fn p(&self) -> &H {
        &self.p
    }

    fn q(&self) -> &H {
        &self.q
    }

    fn dp(&self) -> &H {
        &self.dp
    }

    fn dq(&self) -> &H {
        &self.dq
    }

    fn q_inv(&self) -> &H {
        &self.q_inv
    }
}

/// Wipes every integer. Constant time, as the `Zeroize` of `T` and `H` is.
impl<T: Zeroize, H: Zeroize> Drop for RsaPrivateCrtKeyOwned<T, H> {
    fn drop(&mut self) {
        self.modulus.zeroize();
        self.public_exponent.zeroize();
        self.private_exponent.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.q_inv.zeroize();
    }
}

impl<T: Zeroize, H: Zeroize> ZeroizeOnDrop for RsaPrivateCrtKeyOwned<T, H> {}
