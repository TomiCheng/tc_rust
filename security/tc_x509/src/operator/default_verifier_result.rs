use tc_algo::signer::Signer;

use crate::X509Error;
use crate::operator::verifier::Verifier;

// BC's DefaultVerifierResult: whether a signature is that of what was written into the signer,
// which holds the public key. The signer then starts the next message, so ask once
pub struct DefaultVerifierResult {
    signer: Box<dyn Signer>,
}

impl DefaultVerifierResult {
    pub fn new(signer: Box<dyn Signer>) -> Self {
        Self { signer }
    }
}

impl Verifier for DefaultVerifierResult {
    fn is_verified(&mut self, signature: &[u8]) -> Result<bool, X509Error> {
        Ok(self.signer.verify_signature(signature)?)
    }
}
