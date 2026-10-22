use crate::{CfrgError, KeyGenerationParams, X448PrivateKey, X448PublicKey};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

pub struct X448KeyPairGenerator<'a> {
    params: Option<KeyGenerationParams<'a>>,
}

impl X448KeyPairGenerator<'_> {
    pub fn new() -> Self {
        Self { params: None }
    }
}

impl Default for X448KeyPairGenerator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> KeyPairGeneratorInit<KeyGenerationParams<'a>> for X448KeyPairGenerator<'a> {
    type Error = CfrgError;

    fn init(&mut self, params: KeyGenerationParams<'a>) -> Result<(), CfrgError> {
        todo!()
    }
}

impl KeyPairGenerator for X448KeyPairGenerator<'_> {
    type PublicKey = X448PublicKey;
    type PrivateKey = X448PrivateKey;
    type Error = CfrgError;

    fn generate_key_pair(&mut self) -> Result<(X448PublicKey, X448PrivateKey), CfrgError> {
        todo!()
    }
}
