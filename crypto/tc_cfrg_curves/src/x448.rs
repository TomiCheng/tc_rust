use crate::{CfrgError, KeyGenerationParams, X448PrivateKey, X448PublicKey};
use tc_agreement::{Agreement, AgreementInit};
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

pub struct X448Agreement {
    private_key: Option<X448PrivateKey>,
}

impl X448Agreement {
    pub fn new() -> Self {
        Self { private_key: None }
    }
}

impl Default for X448Agreement {
    fn default() -> Self {
        Self::new()
    }
}

impl AgreementInit<X448PrivateKey> for X448Agreement {
    type Error = CfrgError;

    fn init(&mut self, params: &X448PrivateKey) -> Result<(), CfrgError> {
        todo!()
    }
}

impl Agreement for X448Agreement {
    type PublicKey = X448PublicKey;
    type Error = CfrgError;

    fn agreement_size(&self) -> usize {
        X448PublicKey::SIZE
    }

    fn calculate_agreement(
        &self,
        public_key: &X448PublicKey,
        output: &mut [u8],
    ) -> Result<(), CfrgError> {
        todo!()
    }
}
