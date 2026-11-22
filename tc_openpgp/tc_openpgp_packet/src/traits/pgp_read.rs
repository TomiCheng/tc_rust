use std::io::{self, Read};

use crate::DecodingConfig;

/// A type that can be decoded from its OpenPGP encoding in a byte stream.
pub trait PgpRead: Sized {
    /// Reads the encoding and returns the decoded value.
    fn decode(input: &mut dyn Read, config: &DecodingConfig) -> io::Result<Self>;
}
