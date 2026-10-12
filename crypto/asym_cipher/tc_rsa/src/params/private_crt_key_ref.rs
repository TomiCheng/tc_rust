//! An RSA private key with its CRT values, borrowed from the caller.

use core::sync::atomic::{AtomicBool, Ordering};

use num_traits::Zero;
use tc_bigint::BitOps;
use tc_prime::Primality;

use crate::validation::crt_key_passes;
use crate::{RsaKeyParams, RsaPrivateCrtKeyParams};

/// An RSA private key with the values of the Chinese Remainder Theorem,
/// borrowed from the caller: the modulus and the exponents as integers of
/// type `T`, the primes and the values modulo them as integers of type
/// `H`, all living for `'a`. It is a view only: nothing is checked when it
/// is built, and the operation that takes it calls
/// [`validate`](RsaKeyParams::validate) when it is initialized, which
/// checks the key once and remembers that it passed. The integers are the
/// caller's, and so are theirs to wipe; there is no `Debug`, which would
/// show them.
pub struct RsaPrivateCrtKeyRef<'a, T, H = T> {
    modulus: &'a T,
    public_exponent: &'a T,
    private_exponent: &'a T,
    p: &'a H,
    q: &'a H,
    dp: &'a H,
    dq: &'a H,
    q_inv: &'a H,
    /// Whether the key passed [`validate`](RsaKeyParams::validate), so that
    /// a second call does nothing.
    validated: AtomicBool,
}

impl<'a, T, H> RsaPrivateCrtKeyRef<'a, T, H> {
    /// The key of `modulus`, the exponents `e` and `d`, the primes `p` and
    /// `q`, `d mod (p - 1)`, `d mod (q - 1)` and `q⁻¹ mod p`. Constant
    /// time.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        modulus: &'a T,
        public_exponent: &'a T,
        private_exponent: &'a T,
        p: &'a H,
        q: &'a H,
        dp: &'a H,
        dq: &'a H,
        q_inv: &'a H,
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
}

/// A copy of the view that remembers whether the key passed. Constant time.
impl<T, H> Clone for RsaPrivateCrtKeyRef<'_, T, H> {
    fn clone(&self) -> Self {
        Self {
            validated: AtomicBool::new(self.validated.load(Ordering::Relaxed)),
            ..Self::new(
                self.modulus,
                self.public_exponent,
                self.private_exponent,
                self.p,
                self.q,
                self.dp,
                self.dq,
                self.q_inv,
            )
        }
    }
}

/// A private key, whose exponent is `d`, and the check of
/// [`RsaKeyParams`], once, with that of its CRT values, none of which may
/// be zero, as Bouncy Castle's `RsaPrivateCrtKeyParameters` checks them: a
/// key that passed is not checked again. Constant time, but for
/// `validate`, which is variable time: only for public values, as the
/// modulus is; the other values are only read for zero.
impl<T, H> RsaKeyParams<T> for RsaPrivateCrtKeyRef<'_, T, H>
where
    T: Zero + BitOps + Primality + From<u8>,
    H: Zero,
{
    fn is_private_key(&self) -> bool {
        true
    }

    fn modulus(&self) -> &T {
        self.modulus
    }

    fn exponent(&self) -> &T {
        self.private_exponent
    }

    fn validate(&self) -> bool {
        if self.validated.load(Ordering::Relaxed) {
            return true;
        }
        let crt = [self.p, self.q, self.dp, self.dq, self.q_inv];
        let passes = crt_key_passes(
            self.modulus,
            self.public_exponent,
            self.private_exponent,
            crt,
        );
        self.validated.store(passes, Ordering::Relaxed);
        passes
    }
}

/// The borrowed values. Constant time.
impl<T, H> RsaPrivateCrtKeyParams<T, H> for RsaPrivateCrtKeyRef<'_, T, H>
where
    T: Zero + BitOps + Primality + From<u8>,
    H: Zero,
{
    fn public_exponent(&self) -> &T {
        self.public_exponent
    }

    fn p(&self) -> &H {
        self.p
    }

    fn q(&self) -> &H {
        self.q
    }

    fn dp(&self) -> &H {
        self.dp
    }

    fn dq(&self) -> &H {
        self.dq
    }

    fn q_inv(&self) -> &H {
        self.q_inv
    }
}

#[cfg(test)]
mod tests {
    use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
    use tc_bigint::FixedBigUint;

    use super::RsaPrivateCrtKeyRef;
    use crate::{FixedRsaCrtCoreEngine, RsaKeyParams};

    type Int = FixedBigUint<1>;

    #[test]
    fn a_borrowed_crt_key_decrypts_as_the_plain_key_does() {
        // The toy key p = 1013 and q = 1009, with e = 17: 65 encrypts to 177101.
        let [n, e, d, p, q, dp, dq, q_inv] =
            [1_022_117u32, 17, 180_017, 1013, 1009, 893, 593, 253].map(Int::from);
        let key = RsaPrivateCrtKeyRef::new(&n, &e, &d, &p, &q, &dp, &dq, &q_inv);
        let mut engine = FixedRsaCrtCoreEngine::<1, 1>::new();
        engine.init(CipherDirection::Decrypt, &key).unwrap();
        let mut plaintext = [0; 3];
        engine
            .process_block(&[0x02, 0xb3, 0xcd], &mut plaintext)
            .unwrap();
        assert_eq!(plaintext, [0, 0, 65]);
    }

    #[test]
    fn a_borrowed_crt_key_with_a_zero_value_fails() {
        let [n, e, d, p, q, dp, dq, zero] =
            [1_022_117u32, 17, 180_017, 1013, 1009, 893, 593, 0].map(Int::from);
        assert!(!RsaPrivateCrtKeyRef::new(&n, &e, &d, &p, &q, &dp, &dq, &zero).validate());
    }
}
