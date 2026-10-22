use super::ed448_key::Ed448Key;
use crate::rfc8032::ed448::{self, ExpandedKey};
use crate::{CfrgError, Ed448PrivateKey, Ed448PublicKey};
use alloc::vec::Vec;
use tc_digest::{Digest, Xof};
use tc_keccak::ShakeDigest;
use tc_signer::{Signer, SignerInit};

pub struct Ed448PhSigner {
    context: Vec<u8>,
    key: Option<Ed448Key>,
    prehash: ShakeDigest,
}

impl Ed448PhSigner {
    pub fn new(context: &[u8]) -> Self {
        Self {
            context: context.to_vec(),
            key: None,
            prehash: ShakeDigest::new(256),
        }
    }
}

impl SignerInit<Ed448PrivateKey> for Ed448PhSigner {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed448PrivateKey) -> Result<(), CfrgError> {
        if self.context.len() > 255 {
            return Err(CfrgError::ContextTooLong);
        }
        self.key = Some(Ed448Key::Signing(ExpandedKey::new(params.k())));
        self.reset();
        Ok(())
    }
}

impl SignerInit<Ed448PublicKey> for Ed448PhSigner {
    type Error = CfrgError;

    fn init(&mut self, params: &Ed448PublicKey) -> Result<(), CfrgError> {
        if self.context.len() > 255 {
            return Err(CfrgError::ContextTooLong);
        }
        self.key = Some(Ed448Key::for_verifying(params)?);
        self.reset();
        Ok(())
    }
}

impl Signer for Ed448PhSigner {
    type Error = CfrgError;

    fn max_signature_size(&self) -> usize {
        ed448::SIGNATURE_SIZE
    }

    fn update(&mut self, input: &[u8]) -> Result<(), CfrgError> {
        self.prehash.update(input);
        Ok(())
    }

    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, CfrgError> {
        let key = Ed448Key::signing(&self.key)?;
        let output = output
            .get_mut(..ed448::SIGNATURE_SIZE)
            .ok_or(CfrgError::OutputTooShort)?;
        let (dom, length) = ed448::domain(&self.context, true)?;
        let mut message = [0; 64];
        self.prehash.output_final(&mut message);
        output.copy_from_slice(&ed448::sign(key, &dom[..length], &message));
        self.reset();
        Ok(ed448::SIGNATURE_SIZE)
    }

    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, CfrgError> {
        let public_key = Ed448Key::verifying(&self.key)?;
        let (dom, length) = ed448::domain(&self.context, true)?;
        let mut message = [0; 64];
        self.prehash.output_final(&mut message);
        let valid = signature.try_into().is_ok_and(|signature| {
            ed448::verify(public_key.a(), &dom[..length], &message, signature)
        });
        self.reset();
        Ok(valid)
    }

    fn reset(&mut self) {
        self.prehash.reset();
    }
}
