use super::ed448_key::Ed448Key;
use crate::{CfrgError, Ed448PrivateKey, Ed448PublicKey};
use alloc::vec::Vec;
use tc_signer::{Signer, SignerInit};

// SHAKE256 的預雜湊狀態等 tc_keccak 發行後加入。
pub struct Ed448PhSigner {
    context: Vec<u8>,
    key: Option<Ed448Key>,
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
