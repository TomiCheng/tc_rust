use super::ed25519_key::Ed25519Key;
use crate::rfc8032::ed25519::{self, ExpandedKey};
use crate::{CfrgError, Ed25519PrivateKey, Ed25519PublicKey};
use alloc::vec::Vec;
use tc_digest::Digest;
use tc_sha::Sha512Digest;
use tc_signer::{Signer, SignerInit};

pub struct Ed25519PhSigner {
    context: Vec<u8>,
    key: Option<Ed25519Key>,
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
        if self.context.len() > 255 {
            return Err(CfrgError::ContextTooLong);
        }
        self.key = Some(Ed25519Key::Signing(ExpandedKey::new(params.k())));
        self.reset();
        Ok(())
    }
}

impl SignerInit<Ed25519PublicKey> for Ed25519PhSigner {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed25519PublicKey) -> Result<(), CfrgError> {
        if self.context.len() > 255 {
            return Err(CfrgError::ContextTooLong);
        }
        self.key = Some(Ed25519Key::for_verifying(params)?);
        self.reset();
        Ok(())
    }
}

impl Signer for Ed25519PhSigner {
    type Error = CfrgError;

    fn max_signature_size(&self) -> usize {
        ed25519::SIGNATURE_SIZE
    }

    fn update(&mut self, input: &[u8]) -> Result<(), CfrgError> {
        self.prehash.update(input);
        Ok(())
    }

    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, CfrgError> {
        let key = Ed25519Key::signing(&self.key)?;
        let output = output
            .get_mut(..ed25519::SIGNATURE_SIZE)
            .ok_or(CfrgError::OutputTooShort)?;
        let (dom, length) = ed25519::domain(Some(&self.context), true)?;
        let mut message = [0; 64];
        self.prehash.do_final(&mut message);
        output.copy_from_slice(&ed25519::sign(key, &dom[..length], &message));
        self.reset();
        Ok(ed25519::SIGNATURE_SIZE)
    }

    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, CfrgError> {
        let public_key = Ed25519Key::verifying(&self.key)?;
        let (dom, length) = ed25519::domain(Some(&self.context), true)?;
        let mut message = [0; 64];
        self.prehash.do_final(&mut message);
        let valid = signature.try_into().is_ok_and(|signature| {
            ed25519::verify(public_key.a(), &dom[..length], &message, signature)
        });
        self.reset();
        Ok(valid)
    }

    fn reset(&mut self) {
        self.prehash.reset();
    }
}
