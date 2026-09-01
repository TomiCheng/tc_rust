//! CBC mode implementation.

use alloc::vec;
use alloc::vec::Vec;

use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockModeError, BlockModeInitError,
    CipherDirection,
};
use tc_crypto::AlgorithmName;

use crate::Params;

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

impl<C> AlgorithmName for CbcBlockCipher<C>
where
    C: AlgorithmName,
{
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)?;
        output.write_str("/CBC")
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
        let block_size = self.cipher.block_size();
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

impl<C> BlockCipherInit for CbcBlockCipher<C>
where
    C: BlockCipherInit,
{
    type Params<'a> = Params<'a, C::Params<'a>>;
    type Error = BlockModeInitError<<C as BlockCipherInit>::Error>;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), <Self as BlockCipherInit>::Error> {
        let block_size = self.cipher.block_size();
        match params.iv() {
            Some(iv) if iv.len() != block_size => {
                return Err(BlockModeInitError::InvalidIvLength(iv.len()));
            }
            Some(iv) => self.iv.copy_from_slice(iv),
            None => self.iv.fill(0),
        }

        self.cipher
            .init(direction, params.cipher())
            .map_err(BlockModeInitError::Cipher)?;
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
