use crate::{CfrgError, Ed25519PrivateKey, Ed25519PublicKey, KeyGenerationParams};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

pub struct Ed25519KeyPairGenerator<'a> {
    params: Option<KeyGenerationParams<'a>>,
}

impl Ed25519KeyPairGenerator<'_> {
    pub fn new() -> Self {
        Self { params: None }
    }
}

impl Default for Ed25519KeyPairGenerator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> KeyPairGeneratorInit<KeyGenerationParams<'a>> for Ed25519KeyPairGenerator<'a> {
    type Error = CfrgError;

    fn init(&mut self, params: KeyGenerationParams<'a>) -> Result<(), CfrgError> {
        todo!()
    }
}

impl KeyPairGenerator for Ed25519KeyPairGenerator<'_> {
    type PublicKey = Ed25519PublicKey;
    type PrivateKey = Ed25519PrivateKey;
    type Error = CfrgError;

    fn generate_key_pair(&mut self) -> Result<(Ed25519PublicKey, Ed25519PrivateKey), CfrgError> {
        todo!()
    }
}
