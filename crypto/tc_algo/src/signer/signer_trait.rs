use crate::{AlgoError, Params};

pub trait Signer {
    // The key tells the direction: a private key signs, and a public key verifies
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError>;

    // The most that generate_signature writes, in bytes
    fn max_signature_size(&self) -> usize;

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError>;

    // Writes the signature of the message and returns its length
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, AlgoError>;

    // Whether `signature` is the message's. A wrong one is Ok(false), so the caller has to look at
    // the answer
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, AlgoError>;

    fn reset(&mut self);

    // generate_signature with an output of its own
    fn sign(&mut self) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; self.max_signature_size()];
        let written = self.generate_signature(&mut output)?;
        output.truncate(written);
        Ok(output)
    }
}
