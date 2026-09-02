//! RFC 3394 key-wrap engine.

use tc_cipher::{
    BlockCipher, BlockCipherInit, CipherDirection, KeyWrap, KeyWrapInit, WrapDirection,
};
use tc_crypto::AlgorithmName;
use tc_params::OptionalIvParams;

use crate::core::{fixed_time_eq, unwrap_core_into, wrap_core_in_place};
use crate::{Rfc3394Error, Rfc3394InitError};

const BLOCK_BYTES: usize = 16;

/// RFC 3394 key wrapping over block cipher `C`.
pub struct Rfc3394WrapEngine<C> {
    cipher: C,
    reverse_direction: bool,
    iv: [u8; 8],
    direction: Option<WrapDirection>,
}

impl<C> Rfc3394WrapEngine<C> {
    /// Creates a wrapper whose wrap operation uses cipher encryption.
    pub const fn new(cipher: C) -> Self {
        Self::with_reverse_direction(cipher, false)
    }

    /// Selects whether wrapping uses the cipher's decryption direction.
    pub const fn with_reverse_direction(cipher: C, reverse_direction: bool) -> Self {
        Self {
            cipher,
            reverse_direction,
            iv: [0xa6; 8],
            direction: None,
        }
    }

    /// Consumes the wrapper and returns the underlying cipher.
    pub fn into_inner(self) -> C {
        self.cipher
    }
}

impl<C: Default> Default for Rfc3394WrapEngine<C> {
    fn default() -> Self {
        Self::new(C::default())
    }
}

impl<C: AlgorithmName> AlgorithmName for Rfc3394WrapEngine<C> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)?;
        output.write_str("/RFC3394Wrap")
    }
}

impl<C: BlockCipher> Rfc3394WrapEngine<C> {
    fn check_block_size(&self) -> Result<(), Rfc3394Error<C::Error>> {
        let actual = self.cipher.block_size();
        if actual != BLOCK_BYTES {
            return Err(Rfc3394Error::UnsupportedBlockSize {
                actual,
                required: BLOCK_BYTES,
            });
        }
        Ok(())
    }
}

impl<C: BlockCipher> KeyWrap for Rfc3394WrapEngine<C> {
    type Error = Rfc3394Error<C::Error>;

    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.check_block_size()?;
        if input_len < 8 || !input_len.is_multiple_of(8) {
            return Err(Rfc3394Error::InvalidWrapLength);
        }
        input_len
            .checked_add(8)
            .ok_or(Rfc3394Error::InvalidWrapLength)
    }

    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.check_block_size()?;
        if input_len < 16 || !input_len.is_multiple_of(8) {
            return Err(Rfc3394Error::InvalidUnwrapLength);
        }
        Ok(input_len - 8)
    }

    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Wrap) => {}
            Some(WrapDirection::Unwrap) => return Err(Rfc3394Error::NotForWrapping),
            None => return Err(Rfc3394Error::NotInitialised),
        }

        let required = self.wrapped_len(input.len())?;
        if output.len() < required {
            return Err(Rfc3394Error::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        let block = &mut output[..required];
        block[..8].copy_from_slice(&self.iv);
        block[8..].copy_from_slice(input);
        wrap_core_in_place(&mut self.cipher, block).map_err(Rfc3394Error::Cipher)?;
        Ok(required)
    }

    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Unwrap) => {}
            Some(WrapDirection::Wrap) => return Err(Rfc3394Error::NotForUnwrapping),
            None => return Err(Rfc3394Error::NotInitialised),
        }

        let required = self.max_unwrapped_len(input.len())?;
        if output.len() < required {
            return Err(Rfc3394Error::OutputTooShort {
                required,
                available: output.len(),
            });
        }
        let recovered = &mut output[..required];
        let a = match unwrap_core_into(&mut self.cipher, input, recovered) {
            Ok(a) => a,
            Err(error) => {
                recovered.fill(0);
                return Err(Rfc3394Error::Cipher(error));
            }
        };
        if !fixed_time_eq(&a, &self.iv) {
            recovered.fill(0);
            return Err(Rfc3394Error::IntegrityCheckFailed);
        }
        Ok(required)
    }
}

impl<C, P> KeyWrapInit<P> for Rfc3394WrapEngine<C>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: OptionalIvParams + ?Sized,
{
    type Error = Rfc3394InitError<<C as BlockCipherInit<P>>::Error>;

    fn init(&mut self, direction: WrapDirection, params: &P) -> Result<(), Self::Error> {
        let actual = self.cipher.block_size();
        if actual != BLOCK_BYTES {
            return Err(Rfc3394InitError::UnsupportedBlockSize {
                actual,
                required: BLOCK_BYTES,
            });
        }

        let normal_encrypt = direction == WrapDirection::Wrap;
        let encrypt = normal_encrypt != self.reverse_direction;
        let cipher_direction = if encrypt {
            CipherDirection::Encrypt
        } else {
            CipherDirection::Decrypt
        };
        self.iv = match params.optional_iv() {
            Some(iv) => iv
                .try_into()
                .map_err(|_| Rfc3394InitError::InvalidIvLength {
                    actual: iv.len(),
                    required: 8,
                })?,
            None => [0xa6; 8],
        };
        self.cipher
            .init(cipher_direction, params)
            .map_err(Rfc3394InitError::Cipher)?;
        self.direction = Some(direction);
        Ok(())
    }
}
