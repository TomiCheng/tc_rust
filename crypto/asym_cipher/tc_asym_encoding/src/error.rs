//! The errors of the encodings.

use core::fmt;

/// What can go wrong in an encoding over an asymmetric block cipher. `E` is
/// the error of the engine: that of its initialization from `init`, and
/// that of its processing from `process_block`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EncodingError<E> {
    /// The engine failed.
    Cipher(E),
    /// The encoding processed before it was initialized.
    NotInitialized,
    /// The plaintext length to decrypt to is longer than the output block.
    InvalidPlaintextLength,
    /// The input is longer than the input block.
    InputTooLarge,
    /// The output is shorter than the output block.
    OutputTooShort,
    /// The decrypted block is not an encoding of the type the key expects.
    InvalidBlock,
}

impl<E: fmt::Display> fmt::Display for EncodingError<E> {
    /// Writes the message of the error, the engine's own for `Cipher`.
    /// Constant time: errors carry no secret data; output timing depends
    /// on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cipher(error) => error.fmt(f),
            Self::NotInitialized => f.write_str("encoding not initialized"),
            Self::InvalidPlaintextLength => {
                f.write_str("plaintext length exceeds the output block")
            }
            Self::InputTooLarge => f.write_str("input data too large"),
            Self::OutputTooShort => f.write_str("output buffer too short for encoding"),
            Self::InvalidBlock => f.write_str("block incorrect"),
        }
    }
}

impl<E: core::error::Error> core::error::Error for EncodingError<E> {}
