//! The errors of ISO 9796.

use core::fmt;

use tc_rsa_v2::RsaError;

/// What can go wrong in ISO 9796.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Iso9796Error {
    /// The RSA engine failed.
    Cipher(RsaError),
    /// The encoding processed before it was initialized.
    NotInitialized,
    /// The modulus is of a size the encoding does not take.
    UnsupportedKeySize,
    /// The message is empty.
    InputTooShort,
    /// The message is longer than the input block.
    InputTooLarge,
    /// The pad bits to sign with are above seven.
    InvalidPadBits,
    /// The output is shorter than the output block.
    OutputTooShort,
    /// The verified block is not a valid encoding.
    InvalidBlock,
}

impl fmt::Display for Iso9796Error {
    /// Writes the message of the error, the engine's own for `Cipher`.
    /// Constant time: errors carry no secret data; output timing depends
    /// on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cipher(error) => error.fmt(f),
            Self::NotInitialized => f.write_str("encoding not initialized"),
            Self::UnsupportedKeySize => f.write_str("key size not supported by encoding"),
            Self::InputTooShort => f.write_str("input data too short"),
            Self::InputTooLarge => f.write_str("input data too large"),
            Self::InvalidPadBits => f.write_str("pad bits must be at most 7"),
            Self::OutputTooShort => f.write_str("output buffer too short for encoding"),
            Self::InvalidBlock => f.write_str("invalid block"),
        }
    }
}

impl core::error::Error for Iso9796Error {}
