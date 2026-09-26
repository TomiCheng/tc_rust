//! Runtime-sized standard OFB mode.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_zeroize::Zeroize;
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvParams};

/// Output Feedback mode over the block cipher `C`, sized at runtime.
///
/// Available with the `alloc` feature. The engine repeatedly encrypts the
/// feedback register to produce a keystream, and each segment is XORed with
/// its leading bytes. The feedback size, in bits, must be a nonzero multiple
/// of 8 no larger than the engine block; `init` checks it. Encryption and
/// decryption are the same operation, so the requested direction is ignored
/// and the engine is always initialized for encryption. The IV may be at most
/// one block: a shorter one is right-aligned over zeros, so an empty one is
/// all zeros. The IV must never repeat under one key. The state is wiped
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
/// use tc_block_modes::{BlockCipherMode, KeyWithIvRef, OfbBlockCipher};
///
/// let (key, iv) = ([0x42; 16], [0x24; 16]);
/// let mut mode = OfbBlockCipher::new(AesEngine::new(), 64);
/// mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))?;
/// assert_eq!(mode.block_size(), 8);
///
/// let mut ciphertext = [0; 8];
/// mode.process_block(b"8 bytes!", &mut ciphertext)?;
///
/// // Restarting the keystream turns the same call into decryption.
/// mode.reset();
/// let mut recovered = [0; 8];
/// mode.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(&recovered, b"8 bytes!");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct OfbBlockCipher<C> {
    cipher: C,
    feedback_bits: usize,
    iv: Vec<u8>,
    register: Vec<u8>,
    keystream: Vec<u8>,
    initialised: bool,
}

impl<C: BlockCipher> OfbBlockCipher<C> {
    /// Wraps `cipher` with a feedback size expressed in bits and allocates
    /// three blocks of state.
    ///
    /// The feedback size is validated by initialization: it must be a nonzero
    /// multiple of 8 no larger than the cipher block. Constant time: only the
    /// engine's block size is read.
    pub fn new(cipher: C, feedback_bits: usize) -> Self {
        let block_size = cipher.block_size();
        Self {
            cipher,
            feedback_bits,
            iv: vec![0; block_size],
            register: vec![0; block_size],
            keystream: vec![0; block_size],
            initialised: false,
        }
    }
}

impl<C> Drop for OfbBlockCipher<C> {
    /// Wipes the IV and the chaining or keystream state; the engine wipes
    /// its own key schedule. Constant time.
    fn drop(&mut self) {
        self.iv.zeroize();
        self.register.zeroize();
        self.keystream.zeroize();
    }
}

impl<C: Display> Display for OfbBlockCipher<C> {
    /// Writes the engine's name followed by `/OFB` and the feedback size in
    /// bits. Constant time with respect to the key when the engine's `Display`
    /// is; output timing depends on the formatter.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        write!(f, "/OFB{}", self.feedback_bits)
    }
}

impl<C: BlockCipher> BlockCipher for OfbBlockCipher<C> {
    type Error = BlockModeError<C::Error>;

    /// Returns the segment size, the feedback size in bytes. Constant time.
    fn block_size(&self) -> usize {
        self.feedback_bits / 8
    }

    /// XORs the first segment with the next keystream segment and returns its
    /// length.
    ///
    /// Returns `NotInitialised` before a successful `init` and
    /// `BufferTooShort` when either buffer is shorter than a segment, leaving
    /// the register unchanged. Constant time exactly when the engine's
    /// `process_block` is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockModeError::NotInitialised);
        }
        let segment = self.feedback_bits / 8;
        if input.len() < segment || output.len() < segment {
            return Err(BlockModeError::BufferTooShort);
        }

        self.cipher
            .process_block(&self.register, &mut self.keystream)
            .map_err(BlockModeError::Cipher)?;
        for ((output, input), keystream) in output[..segment]
            .iter_mut()
            .zip(input)
            .zip(&self.keystream)
        {
            *output = input ^ keystream;
        }

        let tail = self.register.len() - segment;
        self.register.copy_within(segment.., 0);
        self.register[tail..].copy_from_slice(&self.keystream[..segment]);
        Ok(segment)
    }
}

impl<C, P> BlockCipherInit<P> for OfbBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Checks the feedback size and IV, initializes the engine for encryption,
    /// then installs the IV and restarts the register. The direction is
    /// ignored.
    ///
    /// Returns `InvalidFeedbackSize` for a feedback size that is zero, not a
    /// multiple of 8 or larger than the block, `InvalidIvLength` for an IV
    /// longer than the block, or the engine's error; each leaves the previous
    /// IV and register in place. Constant time exactly when the engine's
    /// `init` is: the mode only checks public lengths and copies the IV.
    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        let block_size = self.cipher.block_size();
        let bits = self.feedback_bits;
        if bits == 0 || bits % 8 != 0 || bits / 8 > block_size {
            return Err(BlockModeInitError::InvalidFeedbackSize(bits));
        }

        let iv = params.iv();
        if iv.len() > block_size {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;

        // new() 之後底層區塊大小可能已變，緩衝區長度以此次 init 為準。
        self.iv.resize(block_size, 0);
        self.register.resize(block_size, 0);
        self.keystream.resize(block_size, 0);
        // 短 IV 靠右放、左補零（FIPS 81），所以空 IV 就是全零。
        let offset = block_size - iv.len();
        self.iv[..offset].fill(0);
        self.iv[offset..].copy_from_slice(iv);
        self.initialised = true;
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher> BlockCipherMode for OfbBlockCipher<C> {
    type Cipher = C;

    /// Returns the wrapped engine. Constant time.
    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }

    /// Returns `true`: a final partial segment can be processed through a
    /// segment-sized buffer. Constant time.
    fn is_partial_block_okay(&self) -> bool {
        true
    }

    /// Restarts the keystream from the IV installed by the last `init`.
    /// Constant time.
    fn reset(&mut self) {
        self.register.copy_from_slice(&self.iv);
        self.keystream.fill(0);
    }
}
