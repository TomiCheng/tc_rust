//! Buffered-cipher adapter for authenticated block-cipher constructions.

use tc_cipher::{
    AeadBlockCipher, AeadCipherInit, BufferedCipher, BufferedCipherInit, CipherDirection,
};
use tc_crypto::AlgorithmName;

use crate::BufferedAeadCipher;

/// Exposes the [`BufferedCipher`] API over an AEAD block cipher `C`.
///
/// The wrapped construction performs its own buffering. This adapter only
/// supplies the common buffered-cipher interface and reports the underlying
/// block cipher's block size.
pub struct BufferedAeadBlockCipher<C> {
    adapter: BufferedAeadCipher<C>,
}

impl<C> BufferedAeadBlockCipher<C> {
    /// Wraps `cipher` without allocating additional buffering state.
    pub const fn new(cipher: C) -> Self {
        Self {
            adapter: BufferedAeadCipher::new(cipher),
        }
    }

    /// Returns the wrapped AEAD block cipher.
    pub const fn inner(&self) -> &C {
        self.adapter.inner()
    }

    /// Consumes the adapter and returns its wrapped AEAD block cipher.
    pub fn into_inner(self) -> C {
        self.adapter.into_inner()
    }
}

impl<C: AlgorithmName> AlgorithmName for BufferedAeadBlockCipher<C> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.adapter.write_algo_name(output)
    }
}

impl<C> BufferedCipher for BufferedAeadBlockCipher<C>
where
    C: AeadBlockCipher,
    C::Error: core::error::Error + 'static,
{
    type Error = <BufferedAeadCipher<C> as BufferedCipher>::Error;

    fn block_size(&self) -> usize {
        self.inner().block_size()
    }

    fn get_update_output_size(&self, input_len: usize) -> usize {
        self.adapter.get_update_output_size(input_len)
    }

    fn get_output_size(&self, input_len: usize) -> usize {
        self.adapter.get_output_size(input_len)
    }

    fn process_byte(&mut self, input: u8, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.adapter.process_byte(input, output)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.adapter.process_bytes(input, output)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.adapter.do_final(output)
    }

    fn reset(&mut self) {
        self.adapter.reset();
    }
}

impl<C, P> BufferedCipherInit<P> for BufferedAeadBlockCipher<C>
where
    C: AeadBlockCipher + AeadCipherInit<P>,
    P: ?Sized,
{
    type Error = <C as AeadCipherInit<P>>::Error;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.adapter.init(direction, params)
    }
}
