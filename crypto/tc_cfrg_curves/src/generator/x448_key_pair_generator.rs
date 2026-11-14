use crate::rfc7748::x448;
use crate::{CfrgError, KeyGenerationParams, X448PrivateKey, X448PublicKey};
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

pub struct X448KeyPairGenerator<R> {
    rng: R,
    initialized: bool,
}

impl<R> X448KeyPairGenerator<R> {
    pub const fn new(rng: R) -> Self {
        Self {
            rng,
            initialized: false,
        }
    }
}

impl<R> KeyPairGeneratorInit<KeyGenerationParams> for X448KeyPairGenerator<R> {
    type Error = CfrgError;

    fn init(&mut self, _params: &KeyGenerationParams) -> Result<(), CfrgError> {
        self.initialized = true;
        Ok(())
    }
}

impl<R: CryptoRng> KeyPairGenerator for X448KeyPairGenerator<R> {
    type PublicKey = X448PublicKey;
    type PrivateKey = X448PrivateKey;
    type Error = CfrgError;

    fn generate_key_pair(&mut self) -> Result<(X448PublicKey, X448PrivateKey), CfrgError> {
        if !self.initialized {
            return Err(CfrgError::NotInitialized);
        }
        let private_key = X448PrivateKey::new(x448::generate_private_key(&mut self.rng));
        let public_key = private_key.generate_public_key();
        Ok((public_key, private_key))
    }
}
