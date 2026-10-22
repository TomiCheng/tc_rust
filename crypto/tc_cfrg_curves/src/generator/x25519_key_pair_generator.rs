use crate::rfc7748::x25519;
use crate::{CfrgError, KeyGenerationParams, X25519PrivateKey, X25519PublicKey};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

pub struct X25519KeyPairGenerator<'a> {
    params: Option<KeyGenerationParams<'a>>,
}

impl X25519KeyPairGenerator<'_> {
    pub fn new() -> Self {
        Self { params: None }
    }
}

impl Default for X25519KeyPairGenerator<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> KeyPairGeneratorInit<KeyGenerationParams<'a>> for X25519KeyPairGenerator<'a> {
    type Error = CfrgError;

    fn init(&mut self, params: KeyGenerationParams<'a>) -> Result<(), CfrgError> {
        self.params = Some(params);
        Ok(())
    }
}

impl KeyPairGenerator for X25519KeyPairGenerator<'_> {
    type PublicKey = X25519PublicKey;
    type PrivateKey = X25519PrivateKey;
    type Error = CfrgError;

    fn generate_key_pair(&mut self) -> Result<(X25519PublicKey, X25519PrivateKey), CfrgError> {
        let params = self.params.as_mut().ok_or(CfrgError::NotInitialized)?;
        let private_key = X25519PrivateKey::new(x25519::generate_private_key(params.rng));
        let public_key = private_key.generate_public_key();
        Ok((public_key, private_key))
    }
}
