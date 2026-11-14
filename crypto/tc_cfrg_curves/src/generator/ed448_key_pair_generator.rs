use crate::rfc8032::ed448;
use crate::{CfrgError, Ed448PrivateKey, Ed448PublicKey, KeyGenerationParams};
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

pub struct Ed448KeyPairGenerator<R> {
    rng: R,
    initialized: bool,
}

impl<R> Ed448KeyPairGenerator<R> {
    pub const fn new(rng: R) -> Self {
        Self {
            rng,
            initialized: false,
        }
    }
}

impl<R> KeyPairGeneratorInit<KeyGenerationParams> for Ed448KeyPairGenerator<R> {
    type Error = CfrgError;

    fn init(&mut self, _params: &KeyGenerationParams) -> Result<(), CfrgError> {
        self.initialized = true;
        Ok(())
    }
}

impl<R: CryptoRng> KeyPairGenerator for Ed448KeyPairGenerator<R> {
    type PublicKey = Ed448PublicKey;
    type PrivateKey = Ed448PrivateKey;
    type Error = CfrgError;

    fn generate_key_pair(&mut self) -> Result<(Ed448PublicKey, Ed448PrivateKey), CfrgError> {
        if !self.initialized {
            return Err(CfrgError::NotInitialized);
        }
        let private_key = Ed448PrivateKey::new(ed448::generate_private_key(&mut self.rng));
        let public_key = private_key.generate_public_key();
        Ok((public_key, private_key))
    }
}
