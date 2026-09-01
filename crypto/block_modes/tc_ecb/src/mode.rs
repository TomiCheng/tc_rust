//! ECB mode implementation.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockCipherMode, CipherDirection};
use tc_crypto::AlgorithmName;

/// Electronic Codebook mode over the block cipher `C`.
pub struct EcbBlockCipher<C> {
    cipher: C,
}

impl<C> EcbBlockCipher<C> {
    /// Wraps `cipher` in ECB mode.
    pub const fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Consumes the mode and returns its underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: AlgorithmName> AlgorithmName for EcbBlockCipher<C> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)?;
        output.write_str("/ECB")
    }
}

impl<C: BlockCipher> BlockCipher for EcbBlockCipher<C> {
    type Error = C::Error;

    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.cipher.process_block(input, output)
    }
}

impl<C: BlockCipherInit> BlockCipherInit for EcbBlockCipher<C> {
    type Params<'a> = C::Params<'a>;
    type Error = <C as BlockCipherInit>::Error;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), <Self as BlockCipherInit>::Error> {
        self.cipher.init(direction, params)
    }
}

impl<C: BlockCipher> BlockCipherMode for EcbBlockCipher<C> {
    type Cipher = C;

    fn underlying_cipher(&self) -> &Self::Cipher {
        &self.cipher
    }

    fn is_partial_block_okay(&self) -> bool {
        false
    }

    fn reset(&mut self) {}
}
