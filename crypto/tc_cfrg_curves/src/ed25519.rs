use crate::{CfrgError, Ed25519PrivateKey, Ed25519PublicKey, KeyGenerationParams};
use alloc::vec::Vec;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_sha::Sha512Digest;
use tc_signer::{Signer, SignerInit};

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

enum Key {
    Signing(Ed25519PrivateKey),
    Verifying(Ed25519PublicKey),
}

pub struct Ed25519Signer {
    key: Option<Key>,
    message: Vec<u8>,
}

impl Ed25519Signer {
    pub fn new() -> Self {
        Self {
            key: None,
            message: Vec::new(),
        }
    }
}

impl SignerInit<Ed25519PrivateKey> for Ed25519Signer {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed25519PrivateKey) -> Result<(), CfrgError> {
        todo!()
    }
}

impl SignerInit<Ed25519PublicKey> for Ed25519Signer {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed25519PublicKey) -> Result<(), CfrgError> {
        todo!()
    }
}

impl Signer for Ed25519Signer {
    type Error = CfrgError;

    fn max_signature_size(&self) -> usize {
        64
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

pub struct Ed25519CtxSigner {
    context: Vec<u8>,
    key: Option<Key>,
    message: Vec<u8>,
}

impl Ed25519CtxSigner {
    pub fn new(context: &[u8]) -> Self {
        Self {
            context: context.to_vec(),
            key: None,
            message: Vec::new(),
        }
    }
}

impl SignerInit<Ed25519PrivateKey> for Ed25519CtxSigner {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed25519PrivateKey) -> Result<(), CfrgError> {
        todo!()
    }
}

impl SignerInit<Ed25519PublicKey> for Ed25519CtxSigner {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed25519PublicKey) -> Result<(), CfrgError> {
        todo!()
    }
}

impl Signer for Ed25519CtxSigner {
    type Error = CfrgError;

    fn max_signature_size(&self) -> usize {
        64
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

pub struct Ed25519PhSigner {
    context: Vec<u8>,
    key: Option<Key>,
    prehash: Sha512Digest,
}

impl Ed25519PhSigner {
    pub fn new(context: &[u8]) -> Self {
        Self {
            context: context.to_vec(),
            key: None,
            prehash: Sha512Digest::new(),
        }
    }
}

impl SignerInit<Ed25519PrivateKey> for Ed25519PhSigner {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed25519PrivateKey) -> Result<(), CfrgError> {
        todo!()
    }
}

impl SignerInit<Ed25519PublicKey> for Ed25519PhSigner {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed25519PublicKey) -> Result<(), CfrgError> {
        todo!()
    }
}

impl Signer for Ed25519PhSigner {
    type Error = CfrgError;

    fn max_signature_size(&self) -> usize {
        64
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
