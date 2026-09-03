//! Buffered adapter for Integrated Encryption Scheme engines.

use alloc::vec;
use alloc::vec::Vec;

use tc_cipher::{
    BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection, IesCipher, IesCipherInit,
};
use tc_crypto::AlgorithmName;

/// Collects a complete message for the one-shot IES engine `E`.
///
/// Updates never emit output. [`BufferedCipher::do_final`] passes the complete
/// buffered message to the engine, clears the buffer regardless of success,
/// and returns the engine's output.
pub struct BufferedIesCipher<E> {
    engine: E,
    buffer: Vec<u8>,
    initialised: bool,
}

impl<E> BufferedIesCipher<E> {
    /// Wraps an IES engine with an initially empty message buffer.
    pub const fn new(engine: E) -> Self {
        Self {
            engine,
            buffer: Vec::new(),
            initialised: false,
        }
    }

    /// Returns the wrapped IES engine.
    pub const fn inner(&self) -> &E {
        &self.engine
    }

    /// Consumes the adapter and returns its wrapped IES engine.
    pub fn into_inner(self) -> E {
        self.engine
    }

    fn clear_buffer(&mut self) {
        self.buffer.fill(0);
        self.buffer.clear();
    }
}

impl<E: AlgorithmName> AlgorithmName for BufferedIesCipher<E> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.engine.write_algo_name(output)
    }
}

impl<E> BufferedCipher for BufferedIesCipher<E>
where
    E: IesCipher,
    E::Error: core::error::Error + 'static,
{
    type Error = BufferedError<E::Error>;

    fn block_size(&self) -> usize {
        0
    }

    fn get_update_output_size(&self, _input_len: usize) -> usize {
        0
    }

    fn get_output_size(&self, input_len: usize) -> usize {
        self.engine
            .get_output_size(self.buffer.len().saturating_add(input_len))
    }

    fn process_byte(&mut self, input: u8, _output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BufferedError::NotInitialised);
        }

        self.buffer.push(input);
        Ok(0)
    }

    fn process_bytes(&mut self, input: &[u8], _output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BufferedError::NotInitialised);
        }

        self.buffer.extend_from_slice(input);
        Ok(0)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BufferedError::NotInitialised);
        }

        let required = self.engine.get_output_size(self.buffer.len());
        if output.len() < required {
            self.clear_buffer();
            return Err(BufferedError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let mut input = core::mem::take(&mut self.buffer);
        let mut block = vec![0; required];
        let result = self
            .engine
            .process_block(&input, &mut block)
            .map_err(BufferedError::Cipher)
            .inspect(|&written| {
                output[..written].copy_from_slice(&block[..written]);
            });
        block.fill(0);
        input.fill(0);
        result
    }

    fn reset(&mut self) {
        self.clear_buffer();
    }
}

impl<E, P> BufferedCipherInit<P> for BufferedIesCipher<E>
where
    E: IesCipherInit<P>,
    P: ?Sized,
{
    type Error = <E as IesCipherInit<P>>::Error;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.initialised = false;
        self.clear_buffer();
        self.engine.init(direction, params)?;
        self.initialised = true;
        Ok(())
    }
}
