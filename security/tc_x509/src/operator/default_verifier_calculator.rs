use std::io;

use tc_algo::signer::Signer;

use crate::operator::verifier::Verifier;
use crate::operator::{DefaultVerifierResult, StreamCalculator};

// BC's DefaultVerifierCalculator: what is written goes into the signer, which must be initialized
// with a public key. A failure of the signer comes out of write as an io::Error, with the
// AlgoError as its inner error
pub struct DefaultVerifierCalculator {
    signer: Box<dyn Signer>,
}

impl DefaultVerifierCalculator {
    pub fn new(signer: Box<dyn Signer>) -> Self {
        Self { signer }
    }
}

impl io::Write for DefaultVerifierCalculator {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.signer.update(buf).map_err(io::Error::other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl StreamCalculator<Box<dyn Verifier>> for DefaultVerifierCalculator {
    fn result(self: Box<Self>) -> Box<dyn Verifier> {
        Box::new(DefaultVerifierResult::new(self.signer))
    }
}
