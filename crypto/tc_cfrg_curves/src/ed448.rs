use crate::{CfrgError, KeyGenerationParams};
use alloc::vec::Vec;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_signer::{Signer, SignerInit};

#[derive(Clone)]
pub struct Ed448PrivateKey([u8; 57]);

impl Ed448PrivateKey {
    pub const SIZE: usize = 57;

    pub fn new(bytes: [u8; 57]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 57] {
        self.0
    }

    pub fn generate_public_key(&self) -> Ed448PublicKey {
        todo!()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed448PublicKey([u8; 57]);

impl Ed448PublicKey {
    pub const SIZE: usize = 57;

    pub fn new(bytes: [u8; 57]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 57] {
        self.0
    }
}

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

enum Key {
    Signing(Ed448PrivateKey),
    Verifying(Ed448PublicKey),
}

pub struct Ed448Signer {
    context: Vec<u8>,
    key: Option<Key>,
    message: Vec<u8>,
}

impl Ed448Signer {
    pub fn new(context: &[u8]) -> Self {
        Self {
            context: context.to_vec(),
            key: None,
            message: Vec::new(),
        }
    }
}

impl SignerInit<Ed448PrivateKey> for Ed448Signer {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed448PrivateKey) -> Result<(), CfrgError> {
        todo!()
    }
}

impl SignerInit<Ed448PublicKey> for Ed448Signer {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed448PublicKey) -> Result<(), CfrgError> {
        todo!()
    }
}

impl Signer for Ed448Signer {
    type Error = CfrgError;

    fn max_signature_size(&self) -> usize {
        114
    }

    fn update(&mut self, input: &[u8]) -> Result<(), CfrgError> {
        todo!()
    }

    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, CfrgError> {
        todo!()
    }

    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, CfrgError> {
        todo!()
    }

    fn reset(&mut self) {
        todo!()
    }
}

// SHAKE256 的預雜湊狀態等 tc_keccak 發行後加入。
pub struct Ed448PhSigner {
    context: Vec<u8>,
    key: Option<Key>,
}

impl Ed448PhSigner {
    pub fn new(context: &[u8]) -> Self {
        Self {
            context: context.to_vec(),
            key: None,
        }
    }
}

impl SignerInit<Ed448PrivateKey> for Ed448PhSigner {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed448PrivateKey) -> Result<(), CfrgError> {
        todo!()
    }
}

impl SignerInit<Ed448PublicKey> for Ed448PhSigner {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed448PublicKey) -> Result<(), CfrgError> {
        todo!()
    }
}

impl Signer for Ed448PhSigner {
    type Error = CfrgError;

    fn max_signature_size(&self) -> usize {
        114
    }

    fn update(&mut self, input: &[u8]) -> Result<(), CfrgError> {
        todo!()
    }

    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, CfrgError> {
        todo!()
    }

    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, CfrgError> {
        todo!()
    }

    fn reset(&mut self) {
        todo!()
    }
}
