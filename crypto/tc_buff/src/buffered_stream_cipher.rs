//! Buffered-cipher adapter for stream ciphers.

use tc_cipher::{
    BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection, StreamCipher,
    StreamCipherInit,
};
use tc_crypto::AlgorithmName;

/// Exposes the `BufferedCipher` API over a stream cipher `C`.
///
/// Unlike [`crate::BufferedBlockCipher`], this adapter does not retain input:
/// every byte is processed immediately and finalization only resets the
/// keystream to the state established by the latest successful initialization.
pub struct BufferedStreamCipher<C> {
    cipher: C,
    initialised: bool,
}

impl<C> BufferedStreamCipher<C> {
    /// Wraps `cipher` without allocating.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            initialised: false,
        }
    }

    /// Returns the wrapped stream cipher.
    pub const fn inner(&self) -> &C {
        &self.cipher
    }

    /// Consumes the adapter and returns its wrapped stream cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: AlgorithmName> AlgorithmName for BufferedStreamCipher<C> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)
    }
}

impl<C> BufferedCipher for BufferedStreamCipher<C>
where
    C: StreamCipher,
    C::Error: core::error::Error + 'static,
{
    type Error = BufferedError<C::Error>;

    fn block_size(&self) -> usize {
        0
    }

    fn get_update_output_size(&self, input_len: usize) -> usize {
        input_len
    }

    fn get_output_size(&self, input_len: usize) -> usize {
        input_len
    }

    fn process_byte(&mut self, input: u8, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BufferedError::NotInitialised);
        }
        if output.is_empty() {
            return Err(BufferedError::OutputTooShort {
                required: 1,
                available: 0,
            });
        }

        output[0] = self
            .cipher
            .return_byte(input)
            .map_err(BufferedError::Cipher)?;
        Ok(1)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BufferedError::NotInitialised);
        }
        if output.len() < input.len() {
            return Err(BufferedError::OutputTooShort {
                required: input.len(),
                available: output.len(),
            });
        }
        if input.is_empty() {
            return Ok(0);
        }

        self.cipher
            .process_bytes(input, output)
            .map_err(BufferedError::Cipher)
    }

    fn do_final(&mut self, _output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BufferedError::NotInitialised);
        }

        self.cipher.reset();
        Ok(0)
    }

    fn reset(&mut self) {
        self.cipher.reset();
    }
}

impl<C, P> BufferedCipherInit<P> for BufferedStreamCipher<C>
where
    C: StreamCipherInit<P>,
    P: ?Sized,
{
    type Error = <C as StreamCipherInit<P>>::Error;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.initialised = false;
        self.cipher.init(direction, params)?;
        self.initialised = true;
        Ok(())
    }
}
