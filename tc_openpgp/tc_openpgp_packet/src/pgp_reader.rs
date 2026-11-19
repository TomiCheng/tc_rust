use std::io::Read;

/// Reads OpenPGP packets from an underlying byte stream.
pub struct PgpReader<R> {
    inner: R,
}

impl<R: Read> PgpReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}
