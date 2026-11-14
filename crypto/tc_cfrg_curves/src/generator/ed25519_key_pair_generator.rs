use crate::rfc8032::ed25519;
use crate::{CfrgError, Ed25519PrivateKey, Ed25519PublicKey, KeyGenerationParams};
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

pub struct Ed25519KeyPairGenerator<R> {
    rng: R,
    initialized: bool,
}

impl<R> Ed25519KeyPairGenerator<R> {
    pub const fn new(rng: R) -> Self {
        Self {
            rng,
            initialized: false,
        }
    }
}

impl<R> KeyPairGeneratorInit<KeyGenerationParams> for Ed25519KeyPairGenerator<R> {
    type Error = CfrgError;

    fn init(&mut self, _params: &KeyGenerationParams) -> Result<(), CfrgError> {
        self.initialized = true;
        Ok(())
    }
}

impl<R: CryptoRng> KeyPairGenerator for Ed25519KeyPairGenerator<R> {
    type PublicKey = Ed25519PublicKey;
    type PrivateKey = Ed25519PrivateKey;
    type Error = CfrgError;

    fn generate_key_pair(&mut self) -> Result<(Ed25519PublicKey, Ed25519PrivateKey), CfrgError> {
        if !self.initialized {
            return Err(CfrgError::NotInitialized);
        }
        let private_key = Ed25519PrivateKey::new(ed25519::generate_private_key(&mut self.rng));
        let public_key = private_key.generate_public_key();
        Ok((public_key, private_key))
    }
}
