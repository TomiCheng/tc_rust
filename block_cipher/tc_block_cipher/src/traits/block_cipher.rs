//! Block-cipher contracts.

use crate::CipherDirection;
use core::error::Error;

/// Processes individual blocks using an initialized cipher.
///
/// This interface does not supply padding, chaining or authentication.
/// Import this trait to access an engine's block-processing methods.
/// Timing guarantees belong to the implementation, not this trait.
pub trait BlockCipher {
    /// The engine's processing error, such as [`crate::BlockError`].
    type Error: Error;

    /// Returns the number of bytes in one cipher block.
    ///
    /// Timing is implementation-defined; consult the concrete engine.
    fn block_size(&self) -> usize;

    /// Transforms one block from `input` into `output`, returning bytes written.
    ///
    /// Both buffers must hold at least [`block_size`](Self::block_size) bytes.
    /// Consult the engine for initialization requirements, handling of longer
    /// buffers, error precedence and output state on failure.
    ///
    /// Timing is implementation-defined; this trait does not guarantee
    /// constant-time processing of keys or data.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Installs parameters and selects the direction of a block cipher.
///
/// `P` describes the engine's accepted parameters. It may be a key container
/// implementing [`crate::KeyParams`] or a richer, algorithm-specific type.
/// Initialization and processing are separate traits so generic callers can
/// state exactly which capabilities they need.
pub trait BlockCipherInit<P: ?Sized> {
    /// The engine's initialization error, such as [`crate::InitError`].
    type Error: Error;

    /// Validates and installs `params` for the requested transformation.
    ///
    /// Key lengths and other restrictions are engine-specific. Consult the
    /// engine before relying on a previous key remaining usable after an error.
    /// Implementations also document whether they copy or expand key material.
    ///
    /// Timing is implementation-defined; this trait does not guarantee
    /// constant-time key setup.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error>;
}
