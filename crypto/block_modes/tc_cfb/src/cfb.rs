//! Runtime-sized standard CFB mode.

use alloc::vec;
use alloc::vec::Vec;
use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockModeError, BlockModeInitError,
    CipherDirection,
};
use tc_crypto::AlgorithmName;
use tc_params::OptionalIvParams;

/// Runtime-sized Cipher Feedback mode over `C`.
pub struct CfbBlockCipher<C> {
    cipher: C,
    segment_size: usize,
    iv: Vec<u8>,
    register: Vec<u8>,
    keystream: Vec<u8>,
    direction: Option<CipherDirection>,
}

impl<C: BlockCipher> CfbBlockCipher<C> {
    /// Wraps `cipher` with a feedback size expressed in bits.
    pub fn new(
        cipher: C,
        feedback_bits: usize,
    ) -> Result<Self, BlockModeInitError<core::convert::Infallible>> {
        let block_size = cipher.block_size();
        if feedback_bits == 0 || !feedback_bits.is_multiple_of(8) || feedback_bits / 8 > block_size
        {
            return Err(BlockModeInitError::InvalidFeedbackSize(feedback_bits));
        }

        Ok(Self {
            cipher,
            segment_size: feedback_bits / 8,
            iv: vec![0; block_size],
            register: vec![0; block_size],
            keystream: vec![0; block_size],
            direction: None,
        })
    }

    /// Consumes the mode and returns its underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: AlgorithmName> AlgorithmName for CfbBlockCipher<C> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)?;
        write!(output, "/CFB{}", self.segment_size * 8)
    }
}

impl<C: BlockCipher> BlockCipher for CfbBlockCipher<C> {
    type Error = BlockModeError<C::Error>;

    fn block_size(&self) -> usize {
        self.segment_size
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(BlockModeError::NotInitialised)?;
        let segment = self.segment_size;
        if input.len() < segment || output.len() < segment {
            return Err(BlockModeError::BufferTooShort);
        }

        self.cipher
            .process_block(&self.register, &mut self.keystream)
            .map_err(BlockModeError::Cipher)?;

        let tail = self.register.len() - segment;
        match direction {
            CipherDirection::Encrypt => {
                for index in 0..segment {
                    output[index] = self.keystream[index] ^ input[index];
                }
                self.register.copy_within(segment.., 0);
                self.register[tail..].copy_from_slice(&output[..segment]);
            }
            CipherDirection::Decrypt => {
                self.register.copy_within(segment.., 0);
                self.register[tail..].copy_from_slice(&input[..segment]);
                for index in 0..segment {
                    output[index] = self.keystream[index] ^ input[index];
                }
            }
        }
        Ok(segment)
    }
}

impl<C, P> BlockCipherInit<P> for CfbBlockCipher<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: OptionalIvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &P,
    ) -> Result<(), <Self as BlockCipherInit<P>>::Error> {
        let block_size = self.cipher.block_size();
        match params.optional_iv() {
            Some(iv) if iv.len() > block_size => {
                return Err(BlockModeInitError::InvalidIvLength(iv.len()));
            }
            Some(iv) => {
                let offset = block_size - iv.len();
                self.iv[..offset].fill(0);
                self.iv[offset..].copy_from_slice(iv);
            }
            None => self.iv.fill(0),
        }

        self.cipher
            .init(CipherDirection::Encrypt, params)
            .map_err(BlockModeInitError::Cipher)?;
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
