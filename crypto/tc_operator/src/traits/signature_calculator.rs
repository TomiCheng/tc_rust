use std::io;

pub trait SignatureCalculator: io::Write {
    type Error;

    fn finish(self) -> Result<Vec<u8>, Self::Error>;
}
