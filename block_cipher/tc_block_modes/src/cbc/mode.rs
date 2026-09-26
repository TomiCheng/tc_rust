//! CBC mode implementation.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvOptParams};

/// Cipher Block Chaining mode over the block cipher `C`.
pub struct CbcBlockCipher<C> {
    cipher: C,
    iv: Vec<u8>,
    chain: Vec<u8>,
    next: Vec<u8>,
    direction: Option<CipherDirection>,
}

impl<C: BlockCipher> CbcBlockCipher<C> {
    /// Wraps `cipher` and allocates three blocks of chaining state.
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

    /// Consumes the mode and returns its underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C> Display for CbcBlockCipher<C>
where
    C: Display,
{
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

    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

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

    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }

    fn is_partial_block_okay(&self) -> bool {
        false
    }

    fn reset(&mut self) {
        self.chain.copy_from_slice(&self.iv);
        self.next.fill(0);
    }
}
