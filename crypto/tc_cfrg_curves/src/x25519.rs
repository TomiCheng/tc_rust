use crate::{CfrgError, KeyGenerationParams};
use tc_agreement::{Agreement, AgreementInit};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

#[derive(Clone)]
pub struct X25519PrivateKey([u8; 32]);

impl X25519PrivateKey {
    pub const SIZE: usize = 32;

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn generate_public_key(&self) -> X25519PublicKey {
        todo!()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519PublicKey([u8; 32]);

impl X25519PublicKey {
    pub const SIZE: usize = 32;

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

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
        todo!()
    }
}

impl KeyPairGenerator for X25519KeyPairGenerator<'_> {
    type PublicKey = X25519PublicKey;
    type PrivateKey = X25519PrivateKey;
    type Error = CfrgError;

    fn generate_key_pair(&mut self) -> Result<(X25519PublicKey, X25519PrivateKey), CfrgError> {
        todo!()
    }
}

pub struct X25519Agreement {
    private_key: Option<X25519PrivateKey>,
}

impl X25519Agreement {
    pub fn new() -> Self {
        Self { private_key: None }
    }
}

impl Default for X25519Agreement {
    fn default() -> Self {
        Self::new()
    }
}

impl AgreementInit<X25519PrivateKey> for X25519Agreement {
    type Error = CfrgError;

    fn init(&mut self, params: &X25519PrivateKey) -> Result<(), CfrgError> {
        todo!()
    }
}

impl Agreement for X25519Agreement {
    type PublicKey = X25519PublicKey;
    type Error = CfrgError;

    fn agreement_size(&self) -> usize {
        X25519PublicKey::SIZE
    }

    fn calculate_agreement(
        &self,
        public_key: &X25519PublicKey,
        output: &mut [u8],
    ) -> Result<(), CfrgError> {
        todo!()
    }
}
