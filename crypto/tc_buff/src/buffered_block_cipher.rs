//! Buffered block cipher implementation.

use alloc::vec;
use alloc::vec::Vec;

use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BufferedCipher, BufferedCipherInit,
    BufferedError, CipherDirection,
};
use tc_crypto::AlgorithmName;
use tc_ecb::EcbBlockCipher;

/// An unpadded buffering layer over the block-cipher mode `C`.
pub struct BufferedBlockCipher<C> {
    cipher_mode: C,
    buffer: Vec<u8>,
    buffered: usize,
    initialised: bool,
}

impl<C: BlockCipherMode> BufferedBlockCipher<C> {
    /// Wraps a block-cipher mode and allocates one block of buffering state.
    ///
    /// # Panics
    ///
    /// Panics if `cipher_mode` reports a block size of zero.
    pub fn new(cipher_mode: C) -> Self {
        let block_size = cipher_mode.block_size();
        assert!(
            block_size > 0,
            "buffered cipher requires a positive block size"
        );

        Self {
            cipher_mode,
            buffer: vec![0; block_size],
            buffered: 0,
            initialised: false,
        }
    }

    /// Returns the wrapped block-cipher mode.
    pub const fn inner(&self) -> &C {
        &self.cipher_mode
    }

    /// Consumes the buffering layer and returns its wrapped mode.
    pub fn into_inner(self) -> C {
        self.cipher_mode
    }

    fn reset_state(&mut self) {
        self.buffer.fill(0);
        self.buffered = 0;
        self.cipher_mode.reset();
    }
}

impl<C: BlockCipher> BufferedBlockCipher<EcbBlockCipher<C>> {
    /// Wraps a bare block cipher in ECB mode and then buffers it.
    pub fn from_cipher(cipher: C) -> Self {
        Self::new(EcbBlockCipher::new(cipher))
    }
}

impl<C: AlgorithmName> AlgorithmName for BufferedBlockCipher<C> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher_mode.write_algo_name(output)
    }
}

impl<C> BufferedCipher for BufferedBlockCipher<C>
where
    C: BlockCipherMode,
    C::Error: core::error::Error + 'static,
{
    type Error = BufferedError<C::Error>;

    fn block_size(&self) -> usize {
        self.buffer.len()
    }

    fn get_update_output_size(&self, input_len: usize) -> usize {
        let total = self.buffered.saturating_add(input_len);
        total - total % self.buffer.len()
    }

    fn get_output_size(&self, input_len: usize) -> usize {
        self.buffered.saturating_add(input_len)
    }

    fn process_byte(&mut self, input: u8, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BufferedError::NotInitialised);
        }

        let required = self.get_update_output_size(1);
        if output.len() < required {
            return Err(BufferedError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        self.buffer[self.buffered] = input;
        self.buffered += 1;
        if self.buffered < self.buffer.len() {
            return Ok(0);
        }

        self.buffered = 0;
        self.cipher_mode
            .process_block(&self.buffer, output)
            .map_err(BufferedError::Cipher)
    }

    fn process_bytes(&mut self, mut input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BufferedError::NotInitialised);
        }
        if input.is_empty() {
            return Ok(0);
        }

        let required = self.get_update_output_size(input.len());
        if output.len() < required {
            return Err(BufferedError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let block_size = self.buffer.len();
        let available = block_size - self.buffered;
        let mut written = 0;

        if input.len() >= available {
            self.buffer[self.buffered..].copy_from_slice(&input[..available]);
            input = &input[available..];
            self.buffered = 0;

            written += self
                .cipher_mode
                .process_block(&self.buffer, &mut output[written..])
                .map_err(BufferedError::Cipher)?;

            while input.len() >= block_size {
                written += self
                    .cipher_mode
                    .process_block(input, &mut output[written..])
                    .map_err(BufferedError::Cipher)?;
                input = &input[block_size..];
            }
        }

        let end = self.buffered + input.len();
        self.buffer[self.buffered..end].copy_from_slice(input);
        self.buffered = end;
        Ok(written)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let result = if !self.initialised {
            Err(BufferedError::NotInitialised)
        } else if self.buffered == 0 {
            Ok(0)
        } else if !self.cipher_mode.is_partial_block_okay() {
            Err(BufferedError::IncompleteLastBlock)
        } else if output.len() < self.buffered {
            Err(BufferedError::OutputTooShort {
                required: self.buffered,
                available: output.len(),
            })
        } else {
            let buffered = self.buffered;
            self.buffer[buffered..].fill(0);
            let mut block = vec![0; self.buffer.len()];
            self.cipher_mode
                .process_block(&self.buffer, &mut block)
                .map_err(BufferedError::Cipher)
                .map(|_| {
                    output[..buffered].copy_from_slice(&block[..buffered]);
                    buffered
                })
        };

        self.reset_state();
        result
    }

    fn reset(&mut self) {
        self.reset_state();
    }
}

impl<C, P> BufferedCipherInit<P> for BufferedBlockCipher<C>
where
    C: BlockCipherMode + BlockCipherInit<P>,
    P: ?Sized,
{
    type Error = <C as BlockCipherInit<P>>::Error;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.initialised = false;
        self.reset_state();
        self.cipher_mode.init(direction, params)?;
        self.initialised = true;
        Ok(())
    }
}
