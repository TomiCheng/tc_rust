use std::io;

pub trait DigestCalculator: io::Write {
    type Error;

    fn finish(self) -> Result<Vec<u8>, Self::Error>;
}
