use std::io;

use tc_signer::Signer;

use crate::VerifierCalculator;

pub struct DefaultVerifierCalculator<S> {
    signer: S,
}

impl<S: Signer> DefaultVerifierCalculator<S> {
    pub fn new(signer: S) -> Self {
        Self { signer }
    }
}

impl<S> io::Write for DefaultVerifierCalculator<S>
where
    S: Signer,
    S::Error: Send + Sync + 'static,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.signer.update(buf).map_err(io::Error::other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<S> VerifierCalculator for DefaultVerifierCalculator<S>
where
    S: Signer,
    S::Error: Send + Sync + 'static,
{
    type Error = S::Error;

    fn verify(mut self, signature: &[u8]) -> Result<bool, S::Error> {
        self.signer.verify_signature(signature)
    }
}
