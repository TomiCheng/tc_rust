use super::ed25519_key::Ed25519Key;
use crate::rfc8032::ed25519::{self, ExpandedKey};
use crate::{CfrgError, Ed25519PrivateKey, Ed25519PublicKey};
use alloc::vec::Vec;
use tc_signer::{Signer, SignerInit};

pub struct Ed25519Signer {
    key: Option<Ed25519Key>,
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

impl Default for Ed25519Signer {
    fn default() -> Self {
        Self::new()
    }
}

impl SignerInit<Ed25519PrivateKey> for Ed25519Signer {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed25519PrivateKey) -> Result<(), CfrgError> {
        self.key = Some(Ed25519Key::Signing(ExpandedKey::new(params.k())));
        self.reset();
        Ok(())
    }
}

impl SignerInit<Ed25519PublicKey> for Ed25519Signer {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed25519PublicKey) -> Result<(), CfrgError> {
        self.key = Some(Ed25519Key::for_verifying(params)?);
        self.reset();
        Ok(())
    }
}

impl Signer for Ed25519Signer {
    type Error = CfrgError;

    fn max_signature_size(&self) -> usize {
        ed25519::SIGNATURE_SIZE
    }

    fn update(&mut self, input: &[u8]) -> Result<(), CfrgError> {
        self.message.extend_from_slice(input);
        Ok(())
    }

    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, CfrgError> {
        let key = Ed25519Key::signing(&self.key)?;
        let output = output
            .get_mut(..ed25519::SIGNATURE_SIZE)
            .ok_or(CfrgError::OutputTooShort)?;
        let (dom, length) = ed25519::domain(None, false)?;
        output.copy_from_slice(&ed25519::sign(key, &dom[..length], &self.message));
        self.reset();
        Ok(ed25519::SIGNATURE_SIZE)
    }

    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, CfrgError> {
        let public_key = Ed25519Key::verifying(&self.key)?;
        let (dom, length) = ed25519::domain(None, false)?;
        let valid = signature.try_into().is_ok_and(|signature| {
            ed25519::verify(public_key.a(), &dom[..length], &self.message, signature)
        });
        self.reset();
        Ok(valid)
    }

    fn reset(&mut self) {
        self.message.clear();
    }
}
