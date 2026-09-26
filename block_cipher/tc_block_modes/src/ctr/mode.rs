//! Runtime-sized CTR/SIC mode.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use super::increment_be;
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvParams};

/// Segmented Integer Counter (CTR) mode over the block cipher `C`, sized at
/// runtime.
///
/// Available with the `alloc` feature. The engine encrypts successive counter
/// blocks to produce a keystream, and each block is XORed with it. Encryption
/// and decryption are the same operation, so the requested direction is
/// ignored and the engine is always initialized for encryption.
///
/// The IV is required. It fills the leading bytes of the counter block and the
/// rest start at zero; it may leave at most `min(8, block / 2)` bytes of
/// counter, so AES needs 8 to 16 bytes. The counter spans the whole block and
/// carries into the IV bytes, so keep each message below
/// `2^(8 * (block - iv_len))` blocks. A counter block must never repeat under
/// one key: never reuse an IV, and keep messages under one key from
/// overlapping. The state is not wiped on drop.
///
/// Constant time exactly when the engine is: the mode adds only XORs, copies
/// and a branch-free counter increment.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_block_modes::{CtrBlockCipher, KeyWithIvRef};
///
/// let (key, nonce) = ([0x42; 16], [0x24; 12]);
/// let params = KeyWithIvRef::new(&key, &nonce);
/// let mut mode = CtrBlockCipher::new(AesEngine::new());
///
/// mode.init(CipherDirection::Encrypt, &params)?;
/// let mut ciphertext = [0; 16];
/// mode.process_block(b"one single block", &mut ciphertext)?;
///
/// // Initializing with the same nonce restarts the keystream.
/// mode.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; 16];
/// mode.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(&recovered, b"one single block");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct SicBlockCipher<C> {
    cipher: C,
    iv: Vec<u8>,
    counter: Vec<u8>,
    keystream: Vec<u8>,
    initialised: bool,
}

impl<C: BlockCipher> SicBlockCipher<C> {
    /// Wraps `cipher` and allocates three blocks of counter state.
    /// Constant time: only the engine's block size is read.
    pub fn new(cipher: C) -> Self {
        let block_size = cipher.block_size();
        Self {
            cipher,
            iv: vec![0; block_size],
            counter: vec![0; block_size],
            keystream: vec![0; block_size],
            initialised: false,
        }
    }

    /// Consumes the mode and returns its underlying cipher. Constant time.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: Display> Display for SicBlockCipher<C> {
    /// Writes the engine's name followed by `/SIC`, Bouncy Castle's name for
    /// CTR. Constant time with respect to the key when the engine's `Display`
    /// is; output timing depends on the formatter.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/SIC")
    }
}

impl<C: BlockCipher> BlockCipher for SicBlockCipher<C> {
    type Error = BlockModeError<C::Error>;

    /// Returns the engine's block size. Constant time when the engine's is.
    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    /// XORs the first block with the next keystream block, advances the
    /// counter and returns the block size.
    ///
    /// Returns `NotInitialised` before a successful `init` and
    /// `BufferTooShort` when either buffer is shorter than a block, leaving
    /// the counter unchanged. Constant time exactly when the engine's
    /// `process_block` is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockModeError::NotInitialised);
        }
        let block_size = self.counter.len();
        if input.len() < block_size || output.len() < block_size {
            return Err(BlockModeError::BufferTooShort);
        }

        self.cipher
            .process_block(&self.counter, &mut self.keystream)
            .map_err(BlockModeError::Cipher)?;
        for ((output, input), keystream) in output[..block_size]
            .iter_mut()
            .zip(input)
            .zip(&self.keystream)
        {
            *output = input ^ keystream;
        }
        increment_be(&mut self.counter);
        Ok(block_size)
    }
}

impl<C, P> BlockCipherInit<P> for SicBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Checks the IV, initializes the engine for encryption, then installs the
    /// IV and restarts the counter. The direction is ignored.
    ///
    /// Returns `InvalidIvLength` for an IV longer than the block or leaving
    /// more than `min(8, block / 2)` bytes of counter, or the engine's error;
    /// each leaves the previous IV and counter in place. Constant time exactly
    /// when the engine's `init` is: the mode only checks public lengths and
    /// copies the IV.
    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        let block_size = self.cipher.block_size();
        let iv = params.iv();
        let max_counter_size = 8.min(block_size / 2);
        if iv.len() > block_size || block_size - iv.len() > max_counter_size {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;

        // new() 之後底層區塊大小可能已變，緩衝區長度以此次 init 為準。
        self.iv.resize(block_size, 0);
        self.counter.resize(block_size, 0);
        self.keystream.resize(block_size, 0);
        self.iv[..iv.len()].copy_from_slice(iv);
        self.iv[iv.len()..].fill(0);
        self.initialised = true;
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher> BlockCipherMode for SicBlockCipher<C> {
    type Cipher = C;

    /// Returns the wrapped engine. Constant time.
    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }

    /// Returns `true`: a final partial block can be processed through a
    /// block-sized buffer. Constant time.
    fn is_partial_block_okay(&self) -> bool {
        true
    }

    /// Restarts the counter from the IV installed by the last `init`.
    /// Constant time.
    fn reset(&mut self) {
        self.counter.copy_from_slice(&self.iv);
        self.keystream.fill(0);
    }
}
