use tc_algo::signer::Signer;

use crate::X509Error;
use crate::operator::BlockResult;

// BC's DefaultSignatureResult: the signature of what was written into the signer. The signer then
// starts the next message, so collect the result once
pub struct DefaultSignatureResult {
    signer: Box<dyn Signer>,
}

impl DefaultSignatureResult {
    pub fn new(signer: Box<dyn Signer>) -> Self {
        Self { signer }
    }
}

impl BlockResult for DefaultSignatureResult {
    fn max_result_length(&self) -> usize {
        self.signer.max_signature_size()
    }

    fn collect_into(&mut self, output: &mut [u8]) -> Result<usize, X509Error> {
        Ok(self.signer.generate_signature(output)?)
    }
}
