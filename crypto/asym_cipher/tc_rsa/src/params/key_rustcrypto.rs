//! An RSA public key of the RustCrypto `rsa` crate.

use rsa::traits::PublicKeyParts;
use rsa::{BoxedUint, RsaPublicKey};

use crate::RsaKeyParams;

/// A public key of the RustCrypto `rsa` crate, as the key of an engine of
/// this crate: its modulus and public exponent, as `rsa` holds them, in
/// [`BoxedUint`].
pub struct RsaKeyRustCrypto {
    key: RsaPublicKey,
}

impl RsaKeyRustCrypto {
    /// The key of `key`. Constant time.
    pub const fn new(key: RsaPublicKey) -> Self {
        Self { key }
    }
}

/// The modulus and the public exponent of the `rsa` key. Constant time.
/// `validate` passes every key, as `rsa` checks one when it builds it
/// through `RsaPublicKey::new`, which a key built through its unchecked
/// constructors skips.
impl RsaKeyParams<BoxedUint> for RsaKeyRustCrypto {
    fn is_private_key(&self) -> bool {
        false
    }

    fn modulus(&self) -> &BoxedUint {
        self.key.n().as_ref()
    }

    fn exponent(&self) -> &BoxedUint {
        self.key.e()
    }

    fn validate(&self) -> bool {
        true
    }
}
