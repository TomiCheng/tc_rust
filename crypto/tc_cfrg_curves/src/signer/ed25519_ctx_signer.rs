use super::ed25519_key::Ed25519Key;
use crate::{CfrgError, Ed25519PrivateKey, Ed25519PublicKey};
use alloc::vec::Vec;
use tc_signer::{Signer, SignerInit};

pub struct Ed25519CtxSigner {
    context: Vec<u8>,
    key: Option<Ed25519Key>,
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
