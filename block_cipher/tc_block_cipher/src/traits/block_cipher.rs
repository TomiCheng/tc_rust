//! Block-cipher contracts.

use core::error::Error;
use crate::CipherDirection;

pub trait BlockCipher {
    type Error: Error;

    fn block_size(&self) -> usize;

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;
}

pub trait BlockCipherInit<P: ?Sized> {
    type Error: Error;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error>;
}