use crate::X509Error;
use crate::operator::BlockResult;

// BC's SimpleBlockResult: a result already worked out, such as a wrapped key. Unlike the results
// over a signer, a MAC or a digest, it gives the same bytes each time it is collected
pub struct SimpleBlockResult {
    result: Vec<u8>,
}

impl SimpleBlockResult {
    pub fn new(result: Vec<u8>) -> Self {
        Self { result }
    }
}

impl BlockResult for SimpleBlockResult {
    fn max_result_length(&self) -> usize {
        self.result.len()
    }

    fn collect_into(&mut self, output: &mut [u8]) -> Result<usize, X509Error> {
        let output = output
            .get_mut(..self.result.len())
            .ok_or(X509Error::OutputTooShort)?;
        output.copy_from_slice(&self.result);
        Ok(self.result.len())
    }
}
