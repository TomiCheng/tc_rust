//! Allocation-free CTR/SIC mode.

use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use super::increment_be;
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvParams};

/// Allocation-free Segmented Integer Counter (CTR) mode over an `N`-byte block
/// cipher.
///
/// The engine encrypts successive counter blocks to produce a keystream, and
/// each block is XORed with it. Encryption and decryption are the same
/// operation, so the requested direction is ignored and the engine is always
/// initialized for encryption.
///
/// The IV is required. It fills the leading bytes of the counter block and the
/// rest start at zero; it may leave at most `min(8, N / 2)` bytes of counter,
/// so AES needs 8 to 16 bytes. The counter spans the whole block and carries
/// into the IV bytes, so keep each message below `2^(8 * (N - iv_len))`
/// blocks. A counter block must never repeat under one key: never reuse an IV,
/// and keep messages under one key from overlapping.
///
/// Initialization rejects an engine whose block size is not `N`. The state is
/// stored inline and not wiped on drop.
///
/// Constant time exactly when the engine is: the mode adds only XORs, copies
/// and a branch-free counter increment.
///
/// # Example
///
/// A 12-byte nonce and a message that ends in a partial block:
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_block_modes::{BlockCipherMode, FixedCtrBlockCipher, KeyWithIvRef};
///
/// fn apply(
///     mode: &mut FixedCtrBlockCipher<AesEngine, 16>,
///     data: &mut [u8],
/// ) -> Result<(), Box<dyn core::error::Error>> {
///     for chunk in data.chunks_mut(16) {
///         let mut block = [0; 16];
///         block[..chunk.len()].copy_from_slice(chunk);
///         let mut keyed = [0; 16];
///         mode.process_block(&block, &mut keyed)?;
///         chunk.copy_from_slice(&keyed[..chunk.len()]);
///     }
///     Ok(())
/// }
///
/// let (key, nonce) = ([0x42; 16], [0x24; 12]);
/// let mut mode = FixedCtrBlockCipher::<_, 16>::new(AesEngine::new());
/// mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &nonce))?;
///
/// let mut data = *b"twenty byte message!";
/// apply(&mut mode, &mut data)?;
/// assert_ne!(&data, b"twenty byte message!");
///
/// mode.reset();
/// apply(&mut mode, &mut data)?;
/// assert_eq!(&data, b"twenty byte message!");
/// assert_eq!(mode.to_string(), "AES/SIC");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedSicBlockCipher<C, const N: usize> {
    cipher: C,
    iv: [u8; N],
    counter: [u8; N],
    keystream: [u8; N],
    initialised: bool,
}

impl<C, const N: usize> FixedSicBlockCipher<C, N> {
    /// Wraps `cipher` without allocating. Constant time: nothing is inspected.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            iv: [0; N],
            counter: [0; N],
            keystream: [0; N],
            initialised: false,
        }
    }

    /// Consumes the mode and returns its underlying cipher. Constant time.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: Display, const N: usize> Display for FixedSicBlockCipher<C, N> {
    /// Writes the engine's name followed by `/SIC`, Bouncy Castle's name for
    /// CTR. Constant time with respect to the key when the engine's `Display`
    /// is; output timing depends on the formatter.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/SIC")
    }
}

impl<C: BlockCipher, const N: usize> BlockCipher for FixedSicBlockCipher<C, N> {
    type Error = BlockModeError<C::Error>;

    /// Returns `N`. Constant time.
    fn block_size(&self) -> usize {
        N
    }

    /// XORs the first `N` bytes with the next keystream block, advances the
    /// counter and returns `N`.
    ///
    /// Returns `NotInitialised` before a successful `init` and
    /// `BufferTooShort` when either buffer is shorter than `N`, leaving the
    /// counter unchanged. Constant time exactly when the engine's
    /// `process_block` is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockModeError::NotInitialised);
        }
        if input.len() < N || output.len() < N {
            return Err(BlockModeError::BufferTooShort);
        }

        self.cipher
            .process_block(&self.counter, &mut self.keystream)
            .map_err(BlockModeError::Cipher)?;
        for ((output, input), keystream) in output[..N].iter_mut().zip(input).zip(&self.keystream) {
            *output = input ^ keystream;
        }
        increment_be(&mut self.counter);
        Ok(N)
    }
}

impl<C, P, const N: usize> BlockCipherInit<P> for FixedSicBlockCipher<C, N>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Checks the block size and IV, initializes the engine for encryption,
    /// then installs the IV and restarts the counter. The direction is
    /// ignored.
    ///
    /// Returns `UnsupportedBlockSize` for an engine whose block is not `N`,
    /// `InvalidIvLength` for an IV longer than `N` or leaving more than
    /// `min(8, N / 2)` bytes of counter, or the engine's error; each leaves
    /// the previous IV and counter in place. Constant time exactly when the
    /// engine's `init` is: the mode only checks public lengths and copies the
    /// IV.
    fn init(
        &mut self,
        _direction: CipherDirection,
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
        let max_counter_size = 8.min(N / 2);
        if iv.len() > N || N - iv.len() > max_counter_size {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;

        self.iv[..iv.len()].copy_from_slice(iv);
        self.iv[iv.len()..].fill(0);
        self.initialised = true;
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher, const N: usize> BlockCipherMode for FixedSicBlockCipher<C, N> {
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
