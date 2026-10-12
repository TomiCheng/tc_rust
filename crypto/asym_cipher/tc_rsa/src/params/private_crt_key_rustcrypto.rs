//! An RSA private key with its CRT values, of the RustCrypto `rsa` crate.

use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BoxedUint, RsaPrivateKey};
use tc_asym_cipher::AsymmetricKeyParams;
use zeroize::Zeroize;

use crate::{RsaError, RsaKeyParams, RsaPrivateCrtKeyParams};

/// A private key of the RustCrypto `rsa` crate with the values of the
/// Chinese Remainder Theorem, as the key of an engine of this crate, in
/// [`BoxedUint`]. `rsa` keeps `q⁻¹ mod p` in Montgomery form, so the key
/// keeps its own copy of it as an integer, wiped on drop; `rsa` wipes the
/// rest. A key of more than two primes, or one `rsa` holds no CRT values
/// for, has no place here.
#[derive(Clone)]
pub struct RsaPrivateCrtKeyRustCrypto {
    key: RsaPrivateKey,
    q_inv: BoxedUint,
}

impl RsaPrivateCrtKeyRustCrypto {
    /// The key of `key`, or `InvalidKey` when it has other than two primes,
    /// or no CRT values. Constant time, apart from the outcome.
    pub fn new(key: RsaPrivateKey) -> Result<Self, RsaError> {
        if key.primes().len() != 2 || key.dp().is_none() || key.dq().is_none() {
            return Err(RsaError::InvalidKey);
        }
        let q_inv = key.qinv().ok_or(RsaError::InvalidKey)?.retrieve();
        Ok(Self { key, q_inv })
    }
}

/// Wipes the copy of `q⁻¹ mod p`; `rsa` wipes its key itself. Constant
/// time.
impl Drop for RsaPrivateCrtKeyRustCrypto {
    fn drop(&mut self) {
        self.q_inv.zeroize();
    }
}

/// Whether the key is private. Constant time.
impl AsymmetricKeyParams for RsaPrivateCrtKeyRustCrypto {
    fn is_private_key(&self) -> bool {
        true
    }
}

/// A private key, whose exponent is `d`. Constant time. `validate` passes
/// every key, as `rsa` checks one when it builds it, which a key built
/// through its unchecked constructors skips.
impl RsaKeyParams<BoxedUint> for RsaPrivateCrtKeyRustCrypto {
    fn modulus(&self) -> &BoxedUint {
        self.key.n().as_ref()
    }

    fn exponent(&self) -> &BoxedUint {
        self.key.d()
    }

    fn validate(&self) -> bool {
        true
    }
}

/// The CRT values of the `rsa` key, its primes in the order it holds them.
/// Constant time.
impl RsaPrivateCrtKeyParams<BoxedUint> for RsaPrivateCrtKeyRustCrypto {
    fn public_exponent(&self) -> &BoxedUint {
        self.key.e()
    }

    fn p(&self) -> &BoxedUint {
        &self.key.primes()[0]
    }

    fn q(&self) -> &BoxedUint {
        &self.key.primes()[1]
    }

    fn dp(&self) -> &BoxedUint {
        self.key.dp().expect("checked when the key was built")
    }

    fn dq(&self) -> &BoxedUint {
        self.key.dq().expect("checked when the key was built")
    }

    fn q_inv(&self) -> &BoxedUint {
        &self.q_inv
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rsa::RsaPrivateKey;
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    use tc_asym_cipher::AsymmetricKeyParams;

    use super::RsaPrivateCrtKeyRustCrypto;
    use crate::{RsaKeyParams, RsaPrivateCrtKeyParams};

    #[test]
    fn a_key_of_rsa_hands_out_the_values_rsa_holds() {
        let key = RsaPrivateKey::new(&mut StdRng::seed_from_u64(1), 1024).unwrap();
        let ours = RsaPrivateCrtKeyRustCrypto::new(key.clone()).unwrap();
        assert!(ours.is_private_key());
        assert_eq!(ours.modulus(), key.n().as_ref());
        assert_eq!(ours.exponent(), key.d());
        assert_eq!(ours.public_exponent(), key.e());
        assert_eq!([ours.p(), ours.q()], [&key.primes()[0], &key.primes()[1]]);
        assert_eq!(Some(ours.dp()), key.dp());
        assert_eq!(Some(ours.dq()), key.dq());
        assert_eq!(ours.q_inv(), &key.qinv().unwrap().retrieve());
    }
}
