//! An RSA private key with its CRT values, held by value.

use tc_zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{RsaKeyParams, RsaPrivateCrtKeyParams};

/// An RSA private key with the values of the Chinese Remainder Theorem,
/// held by value: the modulus and the exponents as integers of type `T`,
/// the primes and the values modulo them as integers of type `H`, so that
/// a fixed-width key can hold them at half its width. It is a container
/// only: nothing is checked when it is built, and the operation that takes
/// it checks it when it is initialized. Every integer is wiped on drop;
/// there is no `Debug`, which would show them.
#[derive(Clone)]
pub struct RsaPrivateCrtKeyOwned<T: Zeroize, H: Zeroize = T> {
    modulus: T,
    public_exponent: T,
    private_exponent: T,
    p: H,
    q: H,
    dp: H,
    dq: H,
    q_inv: H,
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
        }
    }
}

/// A private key, whose exponent is `d`. Constant time.
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
