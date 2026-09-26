//! Allocation-free CTR/SIC mode.

use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use super::increment_be;
use crate::{BlockCipherMode, BlockModeError, BlockModeInitError, IvParams};

/// Allocation-free Segmented Integer Counter (CTR) mode over an `N`-byte block
/// cipher.
///
/// The IV fills the leading bytes of the counter block and the rest start at
/// zero. It may be shorter than `N` by at most `min(8, N / 2)` bytes, which
/// leaves room for the counter. Encryption and decryption are the same
/// operation, so the requested direction is ignored.
pub struct FixedSicBlockCipher<C, const N: usize> {
    cipher: C,
    iv: [u8; N],
    counter: [u8; N],
    keystream: [u8; N],
    initialised: bool,
}

impl<C, const N: usize> FixedSicBlockCipher<C, N> {
    /// Wraps `cipher` without allocating.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            iv: [0; N],
            counter: [0; N],
            keystream: [0; N],
            initialised: false,
        }
    }

    /// Consumes the mode and returns its underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: Display, const N: usize> Display for FixedSicBlockCipher<C, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)?;
        f.write_str("/SIC")
    }
}

impl<C: BlockCipher, const N: usize> BlockCipher for FixedSicBlockCipher<C, N> {
    type Error = BlockModeError<C::Error>;

    fn block_size(&self) -> usize {
        N
    }

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
