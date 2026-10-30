use std::io;

pub trait VerifierCalculator: io::Write {
    type Error;

    fn verify(self, signature: &[u8]) -> Result<bool, Self::Error>;
}
