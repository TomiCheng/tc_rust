//! Shared key-wrap error type.

use tc_block_modes::BlockCipherModeError;
use tc_cipher_core::BlockCipher;

/// A failure raised by a generic key-wrap engine over block cipher `E`.
pub enum WrapError<E: BlockCipher> {
    /// A key-wrap operation was requested before initialization.
    Uninitialised,
    /// The engine was initialized for unwrapping, but wrapping was requested.
    NotForWrapping,
    /// The engine was initialized for wrapping, but unwrapping was requested.
    NotForUnwrapping,
    /// The input length is not valid for wrapping.
    WrapDataLength,
    /// The input length is not valid for unwrapping.
    UnwrapDataLength,
    /// The underlying cipher's block size cannot support the wrap format.
    UnsupportedBlockSize {
        /// Actual block size in bytes.
        actual: usize,
        /// Minimum block size required by the format.
        minimum: usize,
    },
    /// The caller-provided output buffer is shorter than required.
    OutputBufferTooShort {
        /// Required output capacity in bytes.
        required: usize,
        /// Available output capacity in bytes.
        available: usize,
    },
    /// The wrapped data failed its integrity check.
    IntegrityCheckFailed,
    /// An external IV was supplied for unwrapping even though the format
    /// carries its IV inside the wrapped data.
    IvNotAllowedForUnwrap,
    /// An error reported by the underlying block-cipher mode.
    BlockCipherMode(BlockCipherModeError<E>),
}

impl<E: BlockCipher> core::fmt::Debug for WrapError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Uninitialised => f.write_str("Uninitialised"),
            Self::NotForWrapping => f.write_str("NotForWrapping"),
            Self::NotForUnwrapping => f.write_str("NotForUnwrapping"),
            Self::WrapDataLength => f.write_str("WrapDataLength"),
            Self::UnwrapDataLength => f.write_str("UnwrapDataLength"),
            Self::UnsupportedBlockSize { actual, minimum } => f
                .debug_struct("UnsupportedBlockSize")
                .field("actual", actual)
                .field("minimum", minimum)
                .finish(),
            Self::OutputBufferTooShort {
                required,
                available,
            } => f
                .debug_struct("OutputBufferTooShort")
                .field("required", required)
                .field("available", available)
                .finish(),
            Self::IntegrityCheckFailed => f.write_str("IntegrityCheckFailed"),
            Self::IvNotAllowedForUnwrap => f.write_str("IvNotAllowedForUnwrap"),
            Self::BlockCipherMode(error) => f.debug_tuple("BlockCipherMode").field(error).finish(),
        }
    }
}

impl<E: BlockCipher> core::fmt::Display for WrapError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Uninitialised => f.write_str("key wrapper not initialised"),
            Self::NotForWrapping => f.write_str("wrapper not set for wrapping"),
            Self::NotForUnwrapping => f.write_str("wrapper not set for unwrapping"),
            Self::WrapDataLength => f.write_str("invalid wrap data length"),
            Self::UnwrapDataLength => f.write_str("invalid unwrap data length"),
            Self::UnsupportedBlockSize { actual, minimum } => write!(
                f,
                "block size {actual} is too short; this wrapper requires at least {minimum} bytes"
            ),
            Self::OutputBufferTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::IntegrityCheckFailed => f.write_str("integrity check failed"),
            Self::IvNotAllowedForUnwrap => {
                f.write_str("an external IV is not allowed when unwrapping")
            }
            Self::BlockCipherMode(error) => write!(f, "block cipher mode error: {error}"),
        }
    }
}

impl<E: BlockCipher> core::error::Error for WrapError<E> {}
