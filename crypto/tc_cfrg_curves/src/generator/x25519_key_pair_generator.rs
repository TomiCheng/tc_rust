use crate::rfc7748::x25519;
use crate::{CfrgError, KeyGenerationParams, X25519PrivateKey, X25519PublicKey};
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

pub struct X25519KeyPairGenerator<R> {
    rng: R,
    initialized: bool,
}

impl<R> X25519KeyPairGenerator<R> {
    pub const fn new(rng: R) -> Self {
        Self {
            rng,
            initialized: false,
        }
    }
}

impl<R> KeyPairGeneratorInit<KeyGenerationParams> for X25519KeyPairGenerator<R> {
    type Error = CfrgError;

    fn init(&mut self, _params: &KeyGenerationParams) -> Result<(), CfrgError> {
        self.initialized = true;
        Ok(())
    }
}

impl<R: CryptoRng> KeyPairGenerator for X25519KeyPairGenerator<R> {
    type PublicKey = X25519PublicKey;
    type PrivateKey = X25519PrivateKey;
    type Error = CfrgError;

    fn generate_key_pair(&mut self) -> Result<(X25519PublicKey, X25519PrivateKey), CfrgError> {
        if !self.initialized {
            return Err(CfrgError::NotInitialized);
        }
        let private_key = X25519PrivateKey::new(x25519::generate_private_key(&mut self.rng));
        let public_key = private_key.generate_public_key();
        Ok((public_key, private_key))
    }
}
