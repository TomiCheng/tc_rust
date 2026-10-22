use crate::{CfrgError, Ed448PrivateKey, Ed448PublicKey, KeyGenerationParams};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

pub struct Ed448KeyPairGenerator<'a> {
    params: Option<KeyGenerationParams<'a>>,
}

impl Ed448KeyPairGenerator<'_> {
    pub fn new() -> Self {
        Self { params: None }
    }
}

impl Default for Ed448KeyPairGenerator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> KeyPairGeneratorInit<KeyGenerationParams<'a>> for Ed448KeyPairGenerator<'a> {
    type Error = CfrgError;

    fn init(&mut self, params: KeyGenerationParams<'a>) -> Result<(), CfrgError> {
        todo!()
    }
}

impl KeyPairGenerator for Ed448KeyPairGenerator<'_> {
    type PublicKey = Ed448PublicKey;
    type PrivateKey = Ed448PrivateKey;
    type Error = CfrgError;

    fn generate_key_pair(&mut self) -> Result<(Ed448PublicKey, Ed448PrivateKey), CfrgError> {
        todo!()
    }
}
