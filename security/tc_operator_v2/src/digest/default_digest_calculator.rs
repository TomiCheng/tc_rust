use std::io;

use tc_algo_v2::digest::Digest;

use crate::digest::DigestCalculator;

pub(super) struct DefaultDigestCalculator {
    digest: Box<dyn Digest>,
}

impl DefaultDigestCalculator {
    pub(super) fn new(digest: Box<dyn Digest>) -> Self {
        Self { digest }
    }
}

impl io::Write for DefaultDigestCalculator {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.digest.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DigestCalculator for DefaultDigestCalculator {
    fn finish(&mut self) -> Vec<u8> {
        self.digest.finalize()
    }
}
