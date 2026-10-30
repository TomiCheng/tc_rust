use std::io;

use tc_signer::Signer;

use crate::SignatureCalculator;

pub struct DefaultSignatureCalculator<S> {
    signer: S,
}

impl<S: Signer> DefaultSignatureCalculator<S> {
    pub fn new(signer: S) -> Self {
        Self { signer }
    }
}

impl<S> io::Write for DefaultSignatureCalculator<S>
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

impl<S> SignatureCalculator for DefaultSignatureCalculator<S>
where
    S: Signer,
    S::Error: Send + Sync + 'static,
{
    type Error = S::Error;

    fn finish(mut self) -> Result<Vec<u8>, S::Error> {
        let mut signature = vec![0; self.signer.max_signature_size()];
        let len = self.signer.generate_signature(&mut signature)?;
        signature.truncate(len);
        Ok(signature)
    }
}
