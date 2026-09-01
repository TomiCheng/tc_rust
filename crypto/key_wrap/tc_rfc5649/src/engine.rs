//! RFC 5649 key-wrap-with-padding engine.

use tc_cipher::{
    BlockCipher, BlockCipherInit, CipherDirection, KeyWrap, KeyWrapInit, WrapDirection,
};
use tc_crypto::AlgorithmName;
use tc_params::OptionalIvParams;
use tc_rfc3394::{fixed_time_eq, unwrap_core_into, wrap_core_in_place};

use crate::{Rfc5649Error, Rfc5649InitError};

const BLOCK_BYTES: usize = 16;

/// RFC 5649 key wrapping with padding over block cipher `C`.
pub struct Rfc5649WrapEngine<C> {
    cipher: C,
    pre_iv: [u8; 4],
    direction: Option<WrapDirection>,
}

impl<C> Rfc5649WrapEngine<C> {
    /// Creates an uninitialized wrapper using the default AIV prefix.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            pre_iv: [0xa6, 0x59, 0x59, 0xa6],
            direction: None,
        }
    }

    /// Consumes the wrapper and returns the underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: Default> Default for Rfc5649WrapEngine<C> {
    fn default() -> Self {
        Self::new(C::default())
    }
}

impl<C: AlgorithmName> AlgorithmName for Rfc5649WrapEngine<C> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)?;
        output.write_str("/RFC5649Wrap")
    }
}

impl<C: BlockCipher> Rfc5649WrapEngine<C> {
    fn check_block_size(&self) -> Result<(), Rfc5649Error<C::Error>> {
        let actual = self.cipher.block_size();
        if actual != BLOCK_BYTES {
            return Err(Rfc5649Error::UnsupportedBlockSize {
                actual,
                required: BLOCK_BYTES,
            });
        }
        Ok(())
    }
}

impl<C: BlockCipher> KeyWrap for Rfc5649WrapEngine<C> {
    type Error = Rfc5649Error<C::Error>;

    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.check_block_size()?;
        if input_len == 0 || u32::try_from(input_len).is_err() {
            return Err(Rfc5649Error::InvalidWrapLength);
        }
        input_len
            .checked_add(7)
            .map(|length| length & !7)
            .and_then(|length| length.checked_add(8))
            .ok_or(Rfc5649Error::InvalidWrapLength)
    }

    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.check_block_size()?;
        if input_len < 16 || !input_len.is_multiple_of(8) {
            return Err(Rfc5649Error::InvalidUnwrapLength);
        }
        Ok(input_len - 8)
    }

    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Wrap) => {}
            Some(WrapDirection::Unwrap) => return Err(Rfc5649Error::NotForWrapping),
            None => return Err(Rfc5649Error::NotInitialised),
        }
        let required = self.wrapped_len(input.len())?;
        if output.len() < required {
            return Err(Rfc5649Error::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let block = &mut output[..required];
        block.fill(0);
        block[..4].copy_from_slice(&self.pre_iv);
        block[4..8].copy_from_slice(&(input.len() as u32).to_be_bytes());
        block[8..8 + input.len()].copy_from_slice(input);
        wrap_core_in_place(&mut self.cipher, block).map_err(Rfc5649Error::Cipher)?;
        Ok(required)
    }

    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Unwrap) => {}
            Some(WrapDirection::Wrap) => return Err(Rfc5649Error::NotForUnwrapping),
            None => return Err(Rfc5649Error::NotInitialised),
        }
        let required = self.max_unwrapped_len(input.len())?;
        if output.len() < required {
            return Err(Rfc5649Error::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let padded = &mut output[..required];
        let aiv = match unwrap_core_into(&mut self.cipher, input, padded) {
            Ok(aiv) => aiv,
            Err(error) => {
                padded.fill(0);
                return Err(Rfc5649Error::Cipher(error));
            }
        };

        let mut valid = fixed_time_eq(&aiv[..4], &self.pre_iv);
        let message_len = u32::from_be_bytes([aiv[4], aiv[5], aiv[6], aiv[7]]) as usize;
        let upper = padded.len();
        let lower = upper - 8;
        if message_len <= lower || message_len > upper {
            valid = false;
        }
        let padding_len = match upper.checked_sub(message_len) {
            Some(length) if length < 8 => length,
            _ => {
                valid = false;
                4
            }
        };
        let zeroes = [0u8; 8];
        if !fixed_time_eq(&padded[upper - padding_len..], &zeroes[..padding_len]) {
            valid = false;
        }
        if !valid {
            padded.fill(0);
            return Err(Rfc5649Error::IntegrityCheckFailed);
        }
        Ok(message_len)
    }
}

impl<C, P> KeyWrapInit<P> for Rfc5649WrapEngine<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: OptionalIvParams + ?Sized,
{
    type Error = Rfc5649InitError<<C as BlockCipherInit<P>>::Error>;

    fn init(&mut self, direction: WrapDirection, params: &P) -> Result<(), Self::Error> {
        let actual = self.cipher.block_size();
        if actual != BLOCK_BYTES {
            return Err(Rfc5649InitError::UnsupportedBlockSize {
                actual,
                required: BLOCK_BYTES,
            });
        }
        let cipher_direction = match direction {
            WrapDirection::Wrap => CipherDirection::Encrypt,
            WrapDirection::Unwrap => CipherDirection::Decrypt,
        };
        self.pre_iv = match params.optional_iv() {
            Some(iv) => iv
                .try_into()
                .map_err(|_| Rfc5649InitError::InvalidIvLength {
                    actual: iv.len(),
                    required: 4,
                })?,
            None => [0xa6, 0x59, 0x59, 0xa6],
        };
        self.cipher
            .init(cipher_direction, params)
            .map_err(Rfc5649InitError::Cipher)?;
        self.direction = Some(direction);
        Ok(())
    }
}
