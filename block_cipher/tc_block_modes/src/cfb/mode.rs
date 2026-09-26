//! Runtime-sized standard CFB mode.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvOptParams};

/// Runtime-sized Cipher Feedback mode over the block cipher `C`.
pub struct CfbBlockCipher<C> {
    cipher: C,
    feedback_bits: usize,
    iv: Vec<u8>,
    register: Vec<u8>,
    keystream: Vec<u8>,
    direction: Option<CipherDirection>,
}

impl<C: BlockCipher> CfbBlockCipher<C> {
    /// Wraps `cipher` with a feedback size expressed in bits.
    ///
    /// The feedback size is validated by initialization: it must be a nonzero
    /// multiple of 8 no larger than the cipher block.
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

    /// Consumes the mode and returns its underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: Display> Display for CfbBlockCipher<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        write!(f, "/CFB{}", self.feedback_bits)
    }
}

impl<C: BlockCipher> BlockCipher for CfbBlockCipher<C> {
    type Error = BlockModeError<C::Error>;

    fn block_size(&self) -> usize {
        self.feedback_bits / 8
    }

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

    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }

    fn is_partial_block_okay(&self) -> bool {
        true
    }

    fn reset(&mut self) {
        self.register.copy_from_slice(&self.iv);
        self.keystream.fill(0);
    }
}
