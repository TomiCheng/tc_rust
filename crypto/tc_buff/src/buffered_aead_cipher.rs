//! Buffered-cipher adapter for authenticated-encryption ciphers.

use tc_cipher::{
    AeadCipher, AeadCipherInit, BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection,
};
use tc_crypto::AlgorithmName;

/// Exposes the [`BufferedCipher`] API over an AEAD cipher `C`.
///
/// AEAD ciphers already buffer the data required by their construction, so
/// this adapter does not allocate or retain a second copy of the input.
pub struct BufferedAeadCipher<C> {
    cipher: C,
    initialised: bool,
}

impl<C> BufferedAeadCipher<C> {
    /// Wraps `cipher` without allocating.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            initialised: false,
        }
    }

    /// Returns the wrapped AEAD cipher.
    pub const fn inner(&self) -> &C {
        &self.cipher
    }

    /// Consumes the adapter and returns its wrapped AEAD cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }

    fn ensure_output(
        &self,
        required: usize,
        available: usize,
    ) -> Result<(), BufferedError<C::Error>>
    where
        C: AeadCipher,
    {
        if available < required {
            return Err(BufferedError::OutputTooShort {
                required,
                available,
            });
        }
        Ok(())
    }
}

impl<C: AlgorithmName> AlgorithmName for BufferedAeadCipher<C> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)
    }
}

impl<C> BufferedCipher for BufferedAeadCipher<C>
where
    C: AeadCipher,
    C::Error: core::error::Error + 'static,
{
    type Error = BufferedError<C::Error>;

    fn block_size(&self) -> usize {
        0
    }

    fn get_update_output_size(&self, input_len: usize) -> usize {
        self.cipher.get_update_output_size(input_len)
    }

    fn get_output_size(&self, input_len: usize) -> usize {
        self.cipher.get_output_size(input_len)
    }

    fn process_byte(&mut self, input: u8, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BufferedError::NotInitialised);
        }

        self.ensure_output(self.cipher.get_update_output_size(1), output.len())?;
        self.cipher
            .process_bytes(&[input], output)
            .map_err(BufferedError::Cipher)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BufferedError::NotInitialised);
        }

        self.ensure_output(
            self.cipher.get_update_output_size(input.len()),
            output.len(),
        )?;
        self.cipher
            .process_bytes(input, output)
            .map_err(BufferedError::Cipher)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BufferedError::NotInitialised);
        }

        self.ensure_output(self.cipher.get_output_size(0), output.len())?;
        self.cipher.do_final(output).map_err(BufferedError::Cipher)
    }

    fn reset(&mut self) {
        self.cipher.reset();
    }
}

impl<C, P> BufferedCipherInit<P> for BufferedAeadCipher<C>
where
    C: AeadCipherInit<P>,
    P: ?Sized,
{
    type Error = <C as AeadCipherInit<P>>::Error;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.initialised = false;
        self.cipher.init(direction, params)?;
        self.initialised = true;
        Ok(())
    }
}
