//! An RSA key held by value.

use tc_zeroize::{Zeroize, ZeroizeOnDrop};

use crate::RsaKeyParams;

/// An RSA key held by value: a modulus and one exponent, as integers of
/// type `T`. It is a container only: nothing is checked when it is built,
/// and the operation that takes it checks it when it is initialized. Both
/// integers are wiped on drop; there is no `Debug`, which would show the
/// exponent of a private key.
#[derive(Clone)]
pub struct RsaKeyOwned<T: Zeroize> {
    is_private: bool,
    modulus: T,
    exponent: T,
}

impl<T: Zeroize> RsaKeyOwned<T> {
    /// The key of `modulus` and `exponent`, which is `e` for a public key
    /// and `d` for a private one. Constant time.
    pub const fn new(is_private: bool, modulus: T, exponent: T) -> Self {
        Self {
            is_private,
            modulus,
            exponent,
        }
    }
}

/// The fields as they are held. Constant time.
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
