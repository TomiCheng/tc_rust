use std::convert::Infallible;
use std::io;

use tc_digest::Digest;

use crate::DigestCalculator;

pub struct DefaultDigestCalculator<D> {
    digest: D,
}

impl<D: Digest> DefaultDigestCalculator<D> {
    pub fn new(digest: D) -> Self {
        Self { digest }
    }
}

impl<D: Digest> io::Write for DefaultDigestCalculator<D> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.digest.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<D: Digest> DigestCalculator for DefaultDigestCalculator<D> {
    type Error = Infallible;

    fn finish(mut self) -> Result<Vec<u8>, Infallible> {
        let mut output = vec![0; self.digest.digest_size()];
        let len = self.digest.do_final(&mut output);
        output.truncate(len);
        Ok(output)
    }
}
