//! Runtime-sized CTR/SIC mode.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use super::increment_be;
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvParams};

/// Runtime-sized Segmented Integer Counter (CTR) mode over the block cipher
/// `C`.
///
/// The IV fills the leading bytes of the counter block and the rest start at
/// zero. It may be shorter than the block by at most `min(8, block / 2)`
/// bytes, which leaves room for the counter. Encryption and decryption are the
/// same operation, so the requested direction is ignored.
pub struct SicBlockCipher<C> {
    cipher: C,
    iv: Vec<u8>,
    counter: Vec<u8>,
    keystream: Vec<u8>,
    initialised: bool,
}

impl<C: BlockCipher> SicBlockCipher<C> {
    /// Wraps `cipher` and allocates three blocks of counter state.
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

    /// Consumes the mode and returns its underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: Display> Display for SicBlockCipher<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/SIC")
    }
}

impl<C: BlockCipher> BlockCipher for SicBlockCipher<C> {
    type Error = BlockModeError<C::Error>;

    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

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

    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }

    fn is_partial_block_okay(&self) -> bool {
        true
    }

    fn reset(&mut self) {
        self.counter.copy_from_slice(&self.iv);
        self.keystream.fill(0);
    }
}
