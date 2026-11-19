use std::io::{self, Write};

use crate::EncodingConfig;

/// An object that can write its OpenPGP encoding to a byte stream.
pub trait PgpWrite {
    /// Writes the encoding and returns the number of bytes written on success.
    fn encode(&self, writer: &mut dyn Write, config: &EncodingConfig) -> io::Result<u64>;
}
