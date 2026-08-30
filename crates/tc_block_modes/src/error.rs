//! The error type shared by every mode in this crate.

use tc_cipher_core::BlockCipher;

/// A failure raised by a block cipher mode.
///
/// One type is shared by all modes, as `tc_block_cipher` and `tc_stream_cipher`
/// each share one across their implementations. It is generic over the
/// underlying cipher so that cipher's own errors can be reported unchanged.
pub enum BlockCipherModeError<E: BlockCipher> {
    /// A block was processed before `init`.
    NotInitialised,
    /// The initialisation vector length is not valid for this mode.
    ///
    /// CBC requires exactly one block; CFB and OFB accept anything up to one
    /// block (shorter vectors are left-padded with zeros); CTR additionally
    /// requires room for its counter.
    InvalidIvLength {
        /// The IV length supplied.
        actual: usize,
        /// The underlying cipher's block size, which bounds what is accepted.
        block_size: usize,
    },
    /// The feedback size requested for CFB or OFB is not a positive multiple of
    /// eight bits, or exceeds the cipher's block size.
    InvalidFeedbackSize(usize),
    /// The underlying cipher's block size is not the one this mode requires;
    /// GOST's GCTR, for instance, is defined only for 64-bit blocks.
    UnsupportedBlockSize {
        /// The underlying cipher's block size.
        actual: usize,
        /// The block size the mode requires.
        required: usize,
    },
    /// The input or output buffer is shorter than the mode's block size.
    BufferTooShort,
    /// An error reported by the underlying block cipher.
    BlockCipher(E::Error),
}

// Debug 手寫，不用 derive：derive 會對型別參數加上 `E: Debug` 約束（錯的
// 對象），而我們需要的是 `E::Error: Debug`——由 BlockCipher 的
// `type Error: core::error::Error`（其 supertrait 含 Debug）保證。
impl<E: BlockCipher> core::fmt::Debug for BlockCipherModeError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlockCipherModeError::NotInitialised => f.write_str("NotInitialised"),
            BlockCipherModeError::InvalidIvLength { actual, block_size } => f
                .debug_struct("InvalidIvLength")
                .field("actual", actual)
                .field("block_size", block_size)
                .finish(),
            BlockCipherModeError::InvalidFeedbackSize(bits) => {
                f.debug_tuple("InvalidFeedbackSize").field(bits).finish()
            }
            BlockCipherModeError::UnsupportedBlockSize { actual, required } => f
                .debug_struct("UnsupportedBlockSize")
                .field("actual", actual)
                .field("required", required)
                .finish(),
            BlockCipherModeError::BufferTooShort => f.write_str("BufferTooShort"),
            BlockCipherModeError::BlockCipher(e) => f.debug_tuple("BlockCipher").field(e).finish(),
        }
    }
}

impl<E: BlockCipher> core::fmt::Display for BlockCipherModeError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlockCipherModeError::NotInitialised => f.write_str("cipher mode not initialised"),
            BlockCipherModeError::InvalidIvLength { actual, block_size } => write!(
                f,
                "initialisation vector length {actual} is not valid for a {block_size}-byte block"
            ),
            BlockCipherModeError::InvalidFeedbackSize(bits) => write!(
                f,
                "feedback size {bits} must be a positive multiple of 8 bits, up to the block size"
            ),
            BlockCipherModeError::UnsupportedBlockSize { actual, required } => write!(
                f,
                "this mode requires a {required}-byte block, but the cipher has a {actual}-byte block"
            ),
            BlockCipherModeError::BufferTooShort => f.write_str("buffer shorter than one block"),
            BlockCipherModeError::BlockCipher(e) => write!(f, "underlying block cipher error: {e}"),
        }
    }
}

impl<E: BlockCipher> core::error::Error for BlockCipherModeError<E> {}
