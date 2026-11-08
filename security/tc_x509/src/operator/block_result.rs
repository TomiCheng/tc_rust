use crate::X509Error;

// BC's IBlockResult: a result of bytes, such as a signature or a digest, worked out when it is
// collected
pub trait BlockResult {
    // The most that collect_into writes, in bytes
    fn max_result_length(&self) -> usize;

    // Writes the result and returns its length
    fn collect_into(&mut self, output: &mut [u8]) -> Result<usize, X509Error>;

    fn collect(&mut self) -> Result<Vec<u8>, X509Error> {
        let mut output = vec![0; self.max_result_length()];
        let written = self.collect_into(&mut output)?;
        output.truncate(written);
        Ok(output)
    }
}
