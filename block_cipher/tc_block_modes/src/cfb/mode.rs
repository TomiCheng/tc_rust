//! Runtime-sized standard CFB mode.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvOptParams};

/// Cipher Feedback mode over the block cipher `C`, sized at runtime.
///
/// Available with the `alloc` feature. Each segment is XORed with the leading
/// bytes of the encrypted feedback register, and the ciphertext segment is
/// shifted into the register. The feedback size, in bits, must be a nonzero
/// multiple of 8 no larger than the engine block; `init` checks it. The engine
/// is always initialized for encryption. The IV may be at most one block: a
/// shorter one is right-aligned over zeros and an omitted one is all zeros.
/// Use a fresh, unpredictable IV for every message. The state is not wiped on
/// drop.
///
/// Constant time exactly when the engine is: the mode adds only XORs and
/// copies.
///
/// # Example
///
/// CFB128 with a final partial segment, processed through a full-size buffer:
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_block_modes::{CfbBlockCipher, KeyWithIvRef};
///
/// fn transform(
///     mode: &mut CfbBlockCipher<AesEngine>,
///     input: &[u8],
/// ) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
///     let segment = mode.block_size();
///     let mut output = vec![0; input.len()];
///     for (chunk, out) in input.chunks(segment).zip(output.chunks_mut(segment)) {
///         let mut buffer = vec![0; segment];
///         buffer[..chunk.len()].copy_from_slice(chunk);
///         let mut result = vec![0; segment];
///         mode.process_block(&buffer, &mut result)?;
///         out.copy_from_slice(&result[..chunk.len()]);
///     }
///     Ok(output)
/// }
///
/// let (key, iv) = ([0x42; 16], [0x24; 16]);
/// let params = KeyWithIvRef::new(&key, &iv);
/// let message = b"twenty byte message!";
/// let mut mode = CfbBlockCipher::new(AesEngine::new(), 128);
///
/// mode.init(CipherDirection::Encrypt, &params)?;
/// let ciphertext = transform(&mut mode, message)?;
/// mode.init(CipherDirection::Decrypt, &params)?;
/// assert_eq!(transform(&mut mode, &ciphertext)?, message);
/// assert_eq!(mode.to_string(), "AES/CFB128");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct CfbBlockCipher<C> {
    cipher: C,
    feedback_bits: usize,
    iv: Vec<u8>,
    register: Vec<u8>,
    keystream: Vec<u8>,
    direction: Option<CipherDirection>,
}

impl<C: BlockCipher> CfbBlockCipher<C> {
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
            direction: None,
        }
    }

    /// Consumes the mode and returns its underlying cipher. Constant time.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: Display> Display for CfbBlockCipher<C> {
    /// Writes the engine's name followed by `/CFB` and the feedback size in
    /// bits. Constant time with respect to the key when the engine's `Display`
    /// is; output timing depends on the formatter.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        write!(f, "/CFB{}", self.feedback_bits)
    }
}

impl<C: BlockCipher> BlockCipher for CfbBlockCipher<C> {
    type Error = BlockModeError<C::Error>;

    /// Returns the segment size, the feedback size in bytes. Constant time.
    fn block_size(&self) -> usize {
        self.feedback_bits / 8
    }

    /// Encrypts or decrypts the first segment and returns its length.
    ///
    /// Returns `NotInitialised` before a successful `init` and
    /// `BufferTooShort` when either buffer is shorter than a segment, leaving
    /// the register unchanged. Constant time exactly when the engine's
    /// `process_block` is.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(BlockModeError::NotInitialised)?;
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

        let ciphertext = match direction {
            CipherDirection::Encrypt => &output[..segment],
            CipherDirection::Decrypt => &input[..segment],
        };
        let tail = self.register.len() - segment;
        self.register.copy_within(segment.., 0);
        self.register[tail..].copy_from_slice(ciphertext);
        Ok(segment)
    }
}

impl<C, P> BlockCipherInit<P> for CfbBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvOptParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Checks the feedback size and IV, initializes the engine for encryption,
    /// then installs the IV and restarts the register.
    ///
    /// Returns `InvalidFeedbackSize` for a feedback size that is zero, not a
    /// multiple of 8 or larger than the block, `InvalidIvLength` for an IV
    /// longer than the block, or the engine's error; each leaves the previous
    /// IV and register in place. Constant time exactly when the engine's
    /// `init` is: the mode only checks public lengths and copies the IV.
    fn init(
        &mut self,
        direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        let block_size = self.cipher.block_size();
        let bits = self.feedback_bits;
        if bits == 0 || bits % 8 != 0 || bits / 8 > block_size {
            return Err(BlockModeInitError::InvalidFeedbackSize(bits));
        }

        let iv = params.iv_opt();
        if let Some(iv) = iv.filter(|iv| iv.len() > block_size) {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;

        // new() 之後底層區塊大小可能已變，緩衝區長度以此次 init 為準。
        self.iv.resize(block_size, 0);
        self.register.resize(block_size, 0);
        self.keystream.resize(block_size, 0);
        // 短 IV 靠右放、左補零（FIPS 81）；省略 IV 等同全零。
        let iv = iv.unwrap_or(&[]);
        let offset = block_size - iv.len();
        self.iv[..offset].fill(0);
        self.iv[offset..].copy_from_slice(iv);
        self.direction = Some(direction);
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher> BlockCipherMode for CfbBlockCipher<C> {
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

    /// Restarts the register from the IV installed by the last `init`.
    /// Constant time.
    fn reset(&mut self) {
        self.register.copy_from_slice(&self.iv);
        self.keystream.fill(0);
    }
}
