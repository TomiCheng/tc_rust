//! CBC mode implementation.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_zeroize::Zeroize;
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvOptParams};

/// Cipher Block Chaining mode over the block cipher `C`, sized at runtime.
///
/// Available with the `alloc` feature. Each plaintext block is XORed with the
/// previous ciphertext block, the first with the IV, before encryption. The IV
/// must be exactly one block; an omitted IV is all zeros, which exists only
/// for compatibility. Use a fresh, unpredictable IV for every message. The IV
/// and chaining state live in vectors sized from the engine and are wiped
/// on drop.
///
/// Constant time exactly when the engine is: the mode adds only XORs and
/// copies.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_block_modes::{CbcBlockCipher, KeyWithIvOwned};
///
/// let params = KeyWithIvOwned::new(vec![0x42; 16], vec![0x24; 16]);
/// let mut mode = CbcBlockCipher::new(AesEngine::new());
/// mode.init(CipherDirection::Encrypt, &params)?;
/// let mut ciphertext = [0; 16];
/// mode.process_block(b"one single block", &mut ciphertext)?;
///
/// mode.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; 16];
/// mode.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(&recovered, b"one single block");
/// assert_eq!(mode.to_string(), "AES/CBC");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct CbcBlockCipher<C> {
    cipher: C,
    iv: Vec<u8>,
    chain: Vec<u8>,
    next: Vec<u8>,
    direction: Option<CipherDirection>,
}

impl<C: BlockCipher> CbcBlockCipher<C> {
    /// Wraps `cipher` and allocates three blocks of chaining state.
    /// Constant time: only the engine's block size is read.
    pub fn new(cipher: C) -> Self {
        let block_size = cipher.block_size();
        Self {
            cipher,
            iv: vec![0; block_size],
            chain: vec![0; block_size],
            next: vec![0; block_size],
            direction: None,
        }
    }
}

impl<C> Drop for CbcBlockCipher<C> {
    /// Wipes the IV and the chaining or keystream state; the engine wipes
    /// its own key schedule. Constant time.
    fn drop(&mut self) {
        self.iv.zeroize();
        self.chain.zeroize();
        self.next.zeroize();
    }
}

impl<C> Display for CbcBlockCipher<C>
where
    C: Display,
{
    /// Writes the engine's name followed by `/CBC`.
    /// Constant time with respect to the key when the engine's `Display` is;
    /// output timing depends on the formatter.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/CBC")
    }
}

impl<C> BlockCipher for CbcBlockCipher<C>
where
    C: BlockCipher,
{
    type Error = BlockModeError<C::Error>;

    /// Returns the engine's block size. Constant time when the engine's is.
    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    /// Encrypts or decrypts the first block and returns the engine's count.
    ///
    /// Returns `NotInitialised` before a successful `init` and
    /// `BufferTooShort` when either buffer is shorter than a block, leaving
    /// the chaining state unchanged. Constant time exactly when the engine's
    /// `process_block` is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(BlockModeError::NotInitialised)?;
        let block_size = self.chain.len();
        if input.len() < block_size || output.len() < block_size {
            return Err(BlockModeError::BufferTooShort);
        }

        match direction {
            CipherDirection::Encrypt => {
                for (chain, input) in self.chain.iter_mut().zip(input) {
                    *chain ^= input;
                }
                let written = self
                    .cipher
                    .process_block(&self.chain, output)
                    .map_err(BlockModeError::Cipher)?;
                self.chain.copy_from_slice(&output[..block_size]);
                Ok(written)
            }
            CipherDirection::Decrypt => {
                self.next.copy_from_slice(&input[..block_size]);
                let written = self
                    .cipher
                    .process_block(input, output)
                    .map_err(BlockModeError::Cipher)?;
                for (output, chain) in output.iter_mut().zip(&self.chain) {
                    *output ^= chain;
                }
                core::mem::swap(&mut self.chain, &mut self.next);
                Ok(written)
            }
        }
    }
}

impl<C, P> BlockCipherInit<P> for CbcBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvOptParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Checks the IV, initializes the engine, then installs the IV and
    /// restarts the chain.
    ///
    /// Returns `InvalidIvLength` for an IV that is not one block, or the
    /// engine's error; each leaves the previous IV and chaining state in
    /// place. Constant time exactly when the engine's `init` is: the mode only
    /// checks public lengths and copies the IV.
    fn init(
        &mut self,
        direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        let block_size = self.cipher.block_size();
        let iv = params.iv_opt();
        if let Some(iv) = iv.filter(|iv| iv.len() != block_size) {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        self.cipher
            .init(direction, params)
            .map_err(BlockModeInitError::Cipher)?;

        // new() 之後底層區塊大小可能已變，緩衝區長度以此次 init 為準。
        self.iv.resize(block_size, 0);
        self.chain.resize(block_size, 0);
        self.next.resize(block_size, 0);
        match iv {
            Some(iv) => self.iv.copy_from_slice(iv),
            None => self.iv.fill(0),
        }
        self.direction = Some(direction);
        self.reset();
        Ok(())
    }
}

impl<C> BlockCipherMode for CbcBlockCipher<C>
where
    C: BlockCipher,
{
    type Cipher = C;

    /// Returns the wrapped engine. Constant time.
    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }

    /// Returns `false`: CBC processes whole blocks only. Constant time.
    fn is_partial_block_okay(&self) -> bool {
        false
    }

    /// Restarts the chain from the IV installed by the last `init`.
    /// Constant time.
    fn reset(&mut self) {
        self.chain.copy_from_slice(&self.iv);
        self.next.fill(0);
    }
}
