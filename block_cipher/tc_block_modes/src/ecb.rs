//! ECB mode implementation.

use crate::BlockCipherMode;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};

/// Electronic Codebook mode over the block cipher `C`.
///
/// Every block is transformed independently with the engine, so equal
/// plaintext blocks give equal ciphertext blocks. Use it only for single
/// blocks or as a building block for other constructions. Initialization,
/// processing and errors are exactly the engine's.
///
/// Constant time exactly when the engine is: the mode adds no work.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_block_modes::EcbBlockCipher;
///
/// let key = [0x42; 16];
/// let mut mode = EcbBlockCipher::new(AesEngine::new());
/// mode.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut ciphertext = [0; 16];
/// mode.process_block(b"one single block", &mut ciphertext)?;
///
/// mode.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; 16];
/// mode.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(&recovered, b"one single block");
/// assert_eq!(mode.to_string(), "AES/ECB");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct EcbBlockCipher<C> {
    cipher: C,
}

impl<C> EcbBlockCipher<C> {
    /// Wraps `cipher` in ECB mode. Constant time: nothing is inspected.
    pub const fn new(cipher: C) -> Self {
        Self { cipher }
    }
}

impl<C: Display> Display for EcbBlockCipher<C> {
    /// Writes the engine's name followed by `/ECB`.
    /// Constant time with respect to the key when the engine's `Display` is;
    /// output timing depends on the formatter.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/ECB")
    }
}

impl<C: BlockCipher> BlockCipher for EcbBlockCipher<C> {
    type Error = C::Error;

    /// Returns the engine's block size. Constant time when the engine's is.
    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    /// Transforms one block with the engine and returns what it returns.
    /// Constant time exactly when the engine's `process_block` is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.cipher.process_block(input, output)
    }
}

impl<C, P: ?Sized> BlockCipherInit<P> for EcbBlockCipher<C>
where
    C: BlockCipherInit<P>,
{
    type Error = <C as BlockCipherInit<P>>::Error;

    /// Initializes the engine with `direction` and `params`, unchanged.
    /// Constant time exactly when the engine's `init` is.
    fn init(
        &mut self,
        direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        self.cipher.init(direction, params)
    }
}

impl<C: BlockCipher> BlockCipherMode for EcbBlockCipher<C> {
    type Cipher = C;

    /// Returns the wrapped engine. Constant time.
    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }

    /// Returns `false`: ECB processes whole blocks only. Constant time.
    fn is_partial_block_okay(&self) -> bool {
        false
    }

    /// Does nothing: ECB keeps no state between blocks. Constant time.
    fn reset(&mut self) {}
}
