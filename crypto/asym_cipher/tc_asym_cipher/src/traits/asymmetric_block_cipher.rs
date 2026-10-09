//! Asymmetric block-cipher contracts.

use crate::CipherDirection;

/// An initialized public-key block cipher.
///
/// Unlike a symmetric `BlockCipher`, an asymmetric
/// cipher accepts a variable-length input up to [`input_block_size`](Self::input_block_size),
/// and its input and output limits may differ according to the current
/// direction and encoding layer.
///
/// This trait uses a caller-provided output buffer, so the contract itself
/// requires neither `alloc` nor `std`. Initialization is provided independently
/// by [`AsymmetricBlockCipherInit`].
///
/// Implementations with the same [`Error`](AsymmetricBlockCipher::Error) type
/// can be stored behind `dyn AsymmetricBlockCipher<Error = E>` after
/// initialization.
pub trait AsymmetricBlockCipher {
    /// The failure type returned while processing an asymmetric block.
    type Error: core::error::Error;

    /// Returns the maximum input length in bytes for the current direction.
    fn input_block_size(&self) -> usize;

    /// Returns the maximum output length in bytes for the current direction.
    fn output_block_size(&self) -> usize;

    /// Processes one variable-length asymmetric block and returns the number
    /// of bytes written to `output`.
    ///
    /// Returns an error when `input` is longer than
    /// [`input_block_size`](Self::input_block_size), or when `output` is
    /// shorter than [`output_block_size`](Self::output_block_size).
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Initializes an asymmetric block cipher from parameters of type `P`.
///
/// This trait is independent of [`AsymmetricBlockCipher`]. Consumers that
/// need both capabilities use
/// `C: AsymmetricBlockCipher + AsymmetricBlockCipherInit<P>`. Keeping `P` as a
/// trait parameter allows concrete or caller-defined public/private-key
/// parameter types to pass through composing encoding layers.
pub trait AsymmetricBlockCipherInit<P: ?Sized> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the cipher for encryption or decryption.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error>;
}
