use std::io;

pub trait CipherWriter<W>: io::Write {
    type Error;

    fn finish(self) -> Result<W, Self::Error>;
}
