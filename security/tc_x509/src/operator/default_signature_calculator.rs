use std::io;

use tc_algo::signer::Signer;

use crate::operator::{BlockResult, DefaultSignatureResult, StreamCalculator};

// BC's DefaultSignatureCalculator: what is written goes into the signer, which must be initialized
// with a private key. A failure of the signer comes out of write as an io::Error, with the
// AlgoError as its inner error
pub struct DefaultSignatureCalculator {
    signer: Box<dyn Signer>,
}

impl DefaultSignatureCalculator {
    pub fn new(signer: Box<dyn Signer>) -> Self {
        Self { signer }
    }
}

impl io::Write for DefaultSignatureCalculator {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.signer.update(buf).map_err(io::Error::other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl StreamCalculator<Box<dyn BlockResult>> for DefaultSignatureCalculator {
    fn result(self: Box<Self>) -> Box<dyn BlockResult> {
        Box::new(DefaultSignatureResult::new(self.signer))
    }
}
