//! Allocation-free standard OFB mode.

use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_zeroize::Zeroize;
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvParams};

/// Allocation-free Output Feedback mode with an `N`-byte cipher block and an
/// `S`-byte segment.
///
/// The engine repeatedly encrypts the feedback register to produce a
/// keystream, and each segment is XORed with its leading bytes. Encryption and
/// decryption are the same operation, so the requested direction is ignored
/// and the engine is always initialized for encryption. The IV may be at most
/// `N` bytes: a shorter one is right-aligned over zeros, so an empty one is
/// all zeros. The IV must never repeat under one key: a repeat reuses the
/// keystream and reveals the XOR of the two plaintexts.
///
/// Initialization rejects an engine whose block size is not `N` and a segment
/// size outside `1..=N`. The state is stored inline and wiped on drop.
///
/// Constant time exactly when the engine is: the mode adds only XORs and
/// copies.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_block_modes::{FixedOfbBlockCipher, KeyWithIvRef};
///
/// let (key, iv) = ([0x42; 16], [0x24; 16]);
/// let params = KeyWithIvRef::new(&key, &iv);
/// let mut mode = FixedOfbBlockCipher::<_, 16, 16>::new(AesEngine::new());
///
/// mode.init(CipherDirection::Encrypt, &params)?;
/// let mut ciphertext = [0; 16];
/// mode.process_block(b"one single block", &mut ciphertext)?;
///
/// // Decryption applies the same keystream.
/// mode.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; 16];
/// mode.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(&recovered, b"one single block");
/// assert_eq!(mode.to_string(), "AES/OFB128");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedOfbBlockCipher<C, const N: usize, const S: usize> {
    cipher: C,
    iv: [u8; N],
    register: [u8; N],
    keystream: [u8; N],
    initialised: bool,
}

impl<C, const N: usize, const S: usize> FixedOfbBlockCipher<C, N, S> {
    /// Wraps `cipher` without allocating. Constant time: nothing is inspected.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            iv: [0; N],
            register: [0; N],
            keystream: [0; N],
            initialised: false,
        }
    }
}

impl<C, const N: usize, const S: usize> Drop for FixedOfbBlockCipher<C, N, S> {
    /// Wipes the IV and the chaining or keystream state; the engine wipes
    /// its own key schedule. Constant time.
    fn drop(&mut self) {
        self.iv.zeroize();
        self.register.zeroize();
        self.keystream.zeroize();
    }
}

impl<C: Display, const N: usize, const S: usize> Display for FixedOfbBlockCipher<C, N, S> {
    /// Writes the engine's name followed by `/OFB` and the segment size in
    /// bits. Constant time with respect to the key when the engine's `Display`
    /// is; output timing depends on the formatter.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        write!(f, "/OFB{}", S * 8)
    }
}

impl<C: BlockCipher, const N: usize, const S: usize> BlockCipher for FixedOfbBlockCipher<C, N, S> {
    type Error = BlockModeError<C::Error>;

    /// Returns the segment size `S`. Constant time.
    fn block_size(&self) -> usize {
        S
    }

    /// XORs the first `S` bytes with the next keystream segment and returns
    /// `S`.
    ///
    /// Returns `NotInitialised` before a successful `init` and
    /// `BufferTooShort` when either buffer is shorter than `S`, leaving the
    /// register unchanged. Constant time exactly when the engine's
    /// `process_block` is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockModeError::NotInitialised);
        }
        if input.len() < S || output.len() < S {
            return Err(BlockModeError::BufferTooShort);
        }

        self.cipher
            .process_block(&self.register, &mut self.keystream)
            .map_err(BlockModeError::Cipher)?;
        for ((output, input), keystream) in output[..S].iter_mut().zip(input).zip(&self.keystream) {
            *output = input ^ keystream;
        }

        self.register.copy_within(S.., 0);
        self.register[N - S..].copy_from_slice(&self.keystream[..S]);
        Ok(S)
    }
}

impl<C, P, const N: usize, const S: usize> BlockCipherInit<P> for FixedOfbBlockCipher<C, N, S>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Checks the sizes and IV, initializes the engine for encryption, then
    /// installs the IV and restarts the register. The direction is ignored.
    ///
    /// Returns `UnsupportedBlockSize` for an engine whose block is not `N`,
    /// `InvalidFeedbackSize` for a segment outside `1..=N`, `InvalidIvLength`
    /// for an IV longer than `N`, or the engine's error; each leaves the
    /// previous IV and register in place. Constant time exactly when the
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
        if S == 0 || S > N {
            return Err(BlockModeInitError::InvalidFeedbackSize(S * 8));
        }

        let iv = params.iv();
        if iv.len() > N {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;

        // 短 IV 靠右放、左補零（FIPS 81），所以空 IV 就是全零。
        let offset = N - iv.len();
        self.iv[..offset].fill(0);
        self.iv[offset..].copy_from_slice(iv);
        self.initialised = true;
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher, const N: usize, const S: usize> BlockCipherMode
    for FixedOfbBlockCipher<C, N, S>
{
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
