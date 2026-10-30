use std::io;

pub trait MacCalculator: io::Write {
    type Error;

    fn finish(self) -> Result<Vec<u8>, Self::Error>;
}
