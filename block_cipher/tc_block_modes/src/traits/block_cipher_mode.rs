use tc_block_cipher::BlockCipher;

/// An initialized mode of operation over an underlying block cipher.
///
/// Mode initialization uses
/// [`BlockCipherInit`](tc_block_cipher::BlockCipherInit) and processing uses
/// [`BlockCipher`]. This trait adds the mode-specific operations from Bouncy
/// Castle's `IBlockCipherMode` and is usable as `dyn BlockCipherMode`.
///
/// # Example
///
/// Generic code can restart any mode from its IV:
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_block_modes::{BlockCipherMode, FixedCtrBlockCipher, KeyWithIvRef};
///
/// fn first_block_twice<M: BlockCipherMode>(mode: &mut M) -> Result<bool, M::Error> {
///     let (mut first, mut again) = ([0; 16], [0; 16]);
///     mode.process_block(&[0; 16], &mut first)?;
///     mode.reset();
///     mode.process_block(&[0; 16], &mut again)?;
///     Ok(first == again)
/// }
///
/// let (key, nonce) = ([0x42; 16], [0x24; 12]);
/// let mut mode = FixedCtrBlockCipher::<_, 16>::new(AesEngine::new());
/// mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &nonce))?;
/// assert!(first_block_twice(&mut mode)?);
/// assert!(mode.is_partial_block_okay());
/// assert_eq!(mode.underlying_cipher().to_string(), "AES");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub trait BlockCipherMode: BlockCipher {
    /// The block cipher wrapped by this mode.
    type Cipher: BlockCipher + ?Sized;

    /// Returns the underlying block cipher.
    ///
    /// Constant time in every mode of this crate; other implementations
    /// define their own timing.
    fn underlying_cipher(&self) -> &Self::Cipher;

    /// Reports whether a final partial segment can be processed through a
    /// segment-sized buffer, keeping the matching prefix of the output.
    ///
    /// Constant time in every mode of this crate; other implementations
    /// define their own timing.
    fn is_partial_block_okay(&self) -> bool;

    /// Restores the state established by the most recent initialization.
    ///
    /// Constant time in every mode of this crate; other implementations
    /// define their own timing.
    fn reset(&mut self);
}
