use tc_algo_v2::digest::Digest;

use crate::X509Error;
use crate::operator::BlockResult;

// BC's DefaultDigestResult: the hash of what was written into the digest. The digest then starts
// the next message, so collect the result once
pub struct DefaultDigestResult {
    digest: Box<dyn Digest>,
}

impl DefaultDigestResult {
    pub fn new(digest: Box<dyn Digest>) -> Self {
        Self { digest }
    }
}

impl BlockResult for DefaultDigestResult {
    fn max_result_length(&self) -> usize {
        self.digest.digest_size()
    }

    // Digest::do_final may panic on a short output, so the length is checked here first
    fn collect_into(&mut self, output: &mut [u8]) -> Result<usize, X509Error> {
        let required = self.digest.digest_size();
        if output.len() < required {
            return Err(X509Error::OutputTooShort);
        }
        Ok(self.digest.do_final(output))
    }
}
