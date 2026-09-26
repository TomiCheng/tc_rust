use tc_block_cipher::BlockCipher;

/// An initialized mode of operation over an underlying block cipher.
///
/// Mode initialization continues to use [`crate::BlockCipherInit`]. This
/// trait adds the mode-specific operations from Bouncy Castle's
/// `IBlockCipherMode` while remaining usable through `dyn BlockCipherMode`.
pub trait BlockCipherMode: BlockCipher {
    /// The block cipher wrapped by this mode.
    type Cipher: BlockCipher + ?Sized;

    /// Returns the underlying block cipher.
    fn underlying_cipher(&self) -> &Self::Cipher;

    /// Reports whether the mode can process a final partial block.
    fn is_partial_block_okay(&self) -> bool;

    /// Restores the mode state established by the most recent initialization.
    fn reset(&mut self);
}