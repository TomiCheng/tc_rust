use std::io;

use tc_algo::digest::Digest;

use crate::operator::{BlockResult, DefaultDigestResult, StreamCalculator};

// BC's DefaultDigestCalculator: what is written goes into the digest, which cannot fail, so write
// never does
pub struct DefaultDigestCalculator {
    digest: Box<dyn Digest>,
}

impl DefaultDigestCalculator {
    pub fn new(digest: Box<dyn Digest>) -> Self {
        Self { digest }
    }
}

impl io::Write for DefaultDigestCalculator {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.digest.try_update(buf).map_err(io::Error::other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl StreamCalculator<Box<dyn BlockResult>> for DefaultDigestCalculator {
    fn result(self: Box<Self>) -> Box<dyn BlockResult> {
        Box::new(DefaultDigestResult::new(self.digest))
    }
}
