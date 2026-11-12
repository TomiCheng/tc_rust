use tc_algo::digest::Digest;

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

    fn collect_into(&mut self, output: &mut [u8]) -> Result<usize, X509Error> {
        Ok(self.digest.do_final(output)?)
    }
}
