//! Allocation-free CBC mode implementation.

use core::fmt::Display;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvParams};

/// Allocation-free Cipher Block Chaining mode with an `N`-byte block.
///
/// Each plaintext block is XORed with the previous ciphertext block, the first
/// with the IV, before encryption. The IV is required and must be exactly `N`
/// bytes; use a fresh, unpredictable one for every message. Initialization
/// rejects an engine whose block size is not `N`. The IV and chaining state
/// are stored inline as `[u8; N]` and are not wiped on drop.
///
/// Constant time exactly when the engine is: the mode adds only XORs and
/// copies.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_block_modes::{BlockCipherMode, FixedCbcBlockCipher, KeyWithIvFixed};
///
/// let params = KeyWithIvFixed::new([0x42; 16], [0x24; 16]);
/// let mut mode = FixedCbcBlockCipher::<_, 16>::new(AesEngine::new());
/// mode.init(CipherDirection::Encrypt, &params)?;
///
/// let mut first = [0; 16];
/// mode.process_block(b"the same block!!", &mut first)?;
/// let mut second = [0; 16];
/// mode.process_block(b"the same block!!", &mut second)?;
/// assert_ne!(first, second, "chaining hides repeated blocks");
///
/// mode.reset();
/// let mut again = [0; 16];
/// mode.process_block(b"the same block!!", &mut again)?;
/// assert_eq!(again, first, "reset restarts from the IV");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedCbcBlockCipher<C, const N: usize> {
    cipher: C,
    iv: [u8; N],
    chain: [u8; N],
    next: [u8; N],
    direction: Option<CipherDirection>,
}

impl<C, const N: usize> FixedCbcBlockCipher<C, N> {
    /// Wraps `cipher` without allocating. Constant time: nothing is inspected.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            iv: [0; N],
            chain: [0; N],
            next: [0; N],
            direction: None,
        }
    }

    /// Consumes the mode and returns its underlying cipher. Constant time.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: Display, const N: usize> Display for FixedCbcBlockCipher<C, N> {
    /// Writes the engine's name followed by `/CBC`.
    /// Constant time with respect to the key when the engine's `Display` is;
    /// output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        self.cipher.fmt(f)?;
        f.write_str("/CBC")
    }
}

impl<C: BlockCipher, const N: usize> BlockCipher for FixedCbcBlockCipher<C, N> {
    type Error = BlockModeError<C::Error>;

    /// Returns `N`. Constant time.
    fn block_size(&self) -> usize {
        N
    }

    /// Encrypts or decrypts the first `N` bytes and returns the engine's count.
    ///
    /// Returns `NotInitialised` before a successful `init` and
    /// `BufferTooShort` when either buffer is shorter than `N`, leaving the
    /// chaining state unchanged. Constant time exactly when the engine's
    /// `process_block` is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(BlockModeError::NotInitialised)?;
        if input.len() < N || output.len() < N {
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
                self.chain.copy_from_slice(&output[..N]);
                Ok(written)
            }
            CipherDirection::Decrypt => {
                self.next.copy_from_slice(&input[..N]);
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

impl<C, P, const N: usize> BlockCipherInit<P> for FixedCbcBlockCipher<C, N>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Checks the block size and IV, initializes the engine, then installs the
    /// IV and restarts the chain.
    ///
    /// Returns `UnsupportedBlockSize` for an engine whose block is not `N`,
    /// `InvalidIvLength` for an IV that is not `N` bytes, or the engine's
    /// error; each leaves the previous IV and chaining state in place.
    /// Constant time exactly when the engine's `init` is: the mode only checks
    /// public lengths and copies the IV.
    fn init(
        &mut self,
        direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        let actual = self.cipher.block_size();
        if actual != N {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual,
                required: N,
            });
        }

        let iv = params.iv();
        if iv.len() != N {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        self.cipher
            .init(direction, params)
            .map_err(BlockModeInitError::Cipher)?;

        self.iv.copy_from_slice(iv);
        self.direction = Some(direction);
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher, const N: usize> BlockCipherMode for FixedCbcBlockCipher<C, N> {
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
