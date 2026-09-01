//! Allocation-free CBC mode implementation.

use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockModeError, BlockModeInitError,
    CipherDirection,
};
use tc_crypto::AlgorithmName;
use tc_params::OptionalIvParams;

/// Allocation-free Cipher Block Chaining mode with an `N`-byte block.
///
/// Initialization rejects an underlying cipher whose runtime block size is not
/// `N`. The IV and both chaining buffers are stored inline as `[u8; N]`.
pub struct FixedCbcBlockCipher<C, const N: usize> {
    cipher: C,
    iv: [u8; N],
    chain: [u8; N],
    next: [u8; N],
    direction: Option<CipherDirection>,
}

impl<C, const N: usize> FixedCbcBlockCipher<C, N> {
    /// Wraps `cipher` without allocating.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            iv: [0; N],
            chain: [0; N],
            next: [0; N],
            direction: None,
        }
    }

    /// Consumes the mode and returns its underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: AlgorithmName, const N: usize> AlgorithmName for FixedCbcBlockCipher<C, N> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)?;
        output.write_str("/CBC")
    }
}

impl<C: BlockCipher, const N: usize> BlockCipher for FixedCbcBlockCipher<C, N> {
    type Error = BlockModeError<C::Error>;

    fn block_size(&self) -> usize {
        N
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(BlockModeError::NotInitialised)?;
        if input.len() < N || output.len() < N {
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
                self.chain.copy_from_slice(&output[..N]);
                Ok(written)
            }
            CipherDirection::Decrypt => {
                self.next.copy_from_slice(&input[..N]);
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

impl<C, P, const N: usize> BlockCipherInit<P> for FixedCbcBlockCipher<C, N>
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
        let actual = self.cipher.block_size();
        if actual != N {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual,
                required: N,
            });
        }

        match params.optional_iv() {
            Some(iv) if iv.len() != N => {
                return Err(BlockModeInitError::InvalidIvLength(iv.len()));
            }
            Some(iv) => self.iv.copy_from_slice(iv),
            None => self.iv.fill(0),
        }

        self.cipher
            .init(direction, params)
            .map_err(BlockModeInitError::Cipher)?;
        self.direction = Some(direction);
        self.reset();
        Ok(())
    }
}

impl<C: BlockCipher, const N: usize> BlockCipherMode for FixedCbcBlockCipher<C, N> {
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
