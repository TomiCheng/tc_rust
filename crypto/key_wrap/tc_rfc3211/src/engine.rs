//! RFC 3211 key-wrap engine.

use alloc::vec;
use alloc::vec::Vec;

use rand_core::CryptoRng;
use tc_cipher::{
    BlockCipher, BlockCipherInit, CipherDirection, KeyWrap, KeyWrapInit, WrapDirection,
};
use tc_crypto::AlgorithmName;
use tc_params::IvParams;

use crate::{Rfc3211Error, Rfc3211InitError};

const MINIMUM_BLOCK_BYTES: usize = 4;

/// RFC 3211 key wrapping over block cipher `C`.
///
/// Wrapping obtains padding from the caller-provided cryptographically secure
/// RNG. Unwrapping authenticates the embedded length and three complement
/// check bytes before copying recovered key material into the caller's output.
pub struct Rfc3211WrapEngine<C, R> {
    cipher: C,
    rng: R,
    iv: Vec<u8>,
    direction: Option<WrapDirection>,
}

impl<C, R> Rfc3211WrapEngine<C, R> {
    /// Creates an uninitialized RFC 3211 wrapper.
    pub const fn new(cipher: C, rng: R) -> Self {
        Self {
            cipher,
            rng,
            iv: Vec::new(),
            direction: None,
        }
    }

    /// Consumes the wrapper and returns its cipher and RNG.
    pub fn into_inner(self) -> (C, R) {
        (self.cipher, self.rng)
    }
}

impl<C: AlgorithmName, R> AlgorithmName for Rfc3211WrapEngine<C, R> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.cipher.write_algo_name(output)?;
        output.write_str("/RFC3211Wrap")
    }
}

impl<C, R> Rfc3211WrapEngine<C, R>
where
    C: BlockCipher,
{
    fn validate_block_size(&self) -> Result<usize, Rfc3211Error<C::Error>> {
        let block_size = self.cipher.block_size();
        if block_size < MINIMUM_BLOCK_BYTES {
            return Err(Rfc3211Error::UnsupportedBlockSize {
                actual: block_size,
                minimum: MINIMUM_BLOCK_BYTES,
            });
        }
        Ok(block_size)
    }

    fn encrypt_cbc_block(
        &mut self,
        block: &mut [u8],
        chain: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<(), Rfc3211Error<C::Error>> {
        for ((scratch, input), chain) in scratch.iter_mut().zip(block.iter()).zip(chain.iter()) {
            *scratch = *input ^ *chain;
        }
        self.cipher
            .process_block(scratch, block)
            .map_err(Rfc3211Error::Cipher)?;
        chain.copy_from_slice(block);
        Ok(())
    }

    fn decrypt_cbc_block(
        &mut self,
        block: &mut [u8],
        chain: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<(), Rfc3211Error<C::Error>> {
        scratch.copy_from_slice(block);
        self.cipher
            .process_block(scratch, block)
            .map_err(Rfc3211Error::Cipher)?;
        for (output, chain) in block.iter_mut().zip(chain.iter()) {
            *output ^= *chain;
        }
        chain.copy_from_slice(scratch);
        Ok(())
    }
}

impl<C, R> KeyWrap for Rfc3211WrapEngine<C, R>
where
    C: BlockCipher,
    R: CryptoRng,
{
    type Error = Rfc3211Error<C::Error>;

    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if input_len > u8::MAX as usize {
            return Err(Rfc3211Error::InvalidWrapLength);
        }

        let block_size = self.validate_block_size()?;
        let payload_len = input_len
            .checked_add(4)
            .ok_or(Rfc3211Error::InvalidWrapLength)?;
        let minimum_len = block_size
            .checked_mul(2)
            .ok_or(Rfc3211Error::InvalidWrapLength)?;
        let rounded_len = payload_len
            .div_ceil(block_size)
            .checked_mul(block_size)
            .ok_or(Rfc3211Error::InvalidWrapLength)?;

        Ok(core::cmp::max(minimum_len, rounded_len))
    }

    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        let block_size = self.validate_block_size()?;
        let minimum_len = block_size
            .checked_mul(2)
            .ok_or(Rfc3211Error::InvalidUnwrapLength)?;
        if input_len < minimum_len || !input_len.is_multiple_of(block_size) {
            return Err(Rfc3211Error::InvalidUnwrapLength);
        }

        Ok(input_len - 4)
    }

    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Wrap) => {}
            Some(WrapDirection::Unwrap) => return Err(Rfc3211Error::NotForWrapping),
            None => return Err(Rfc3211Error::NotInitialised),
        }

        let required = self.wrapped_len(input.len())?;
        if output.len() < required {
            return Err(Rfc3211Error::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let block_size = self.cipher.block_size();
        let buffer = &mut output[..required];
        buffer[0] = input.len() as u8;
        buffer[4..4 + input.len()].copy_from_slice(input);
        self.rng.fill_bytes(&mut buffer[4 + input.len()..]);
        buffer[1] = !buffer[4];
        buffer[2] = !buffer[5];
        buffer[3] = !buffer[6];

        let mut chain = self.iv.clone();
        let mut scratch = vec![0_u8; block_size];
        for _ in 0..2 {
            for block in buffer.chunks_exact_mut(block_size) {
                if let Err(error) = self.encrypt_cbc_block(block, &mut chain, &mut scratch) {
                    scratch.fill(0);
                    chain.fill(0);
                    return Err(error);
                }
            }
        }

        scratch.fill(0);
        chain.fill(0);
        Ok(required)
    }

    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Unwrap) => {}
            Some(WrapDirection::Wrap) => return Err(Rfc3211Error::NotForUnwrapping),
            None => return Err(Rfc3211Error::NotInitialised),
        }

        let required = self.max_unwrapped_len(input.len())?;
        if output.len() < required {
            return Err(Rfc3211Error::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let block_size = self.cipher.block_size();
        let mut recovered = input.to_vec();
        let mut chain = input[..block_size].to_vec();
        let mut scratch = vec![0_u8; block_size];

        for offset in (block_size..recovered.len()).step_by(block_size) {
            if let Err(error) = self.decrypt_cbc_block(
                &mut recovered[offset..offset + block_size],
                &mut chain,
                &mut scratch,
            ) {
                recovered.fill(0);
                chain.fill(0);
                scratch.fill(0);
                return Err(error);
            }
        }

        chain.copy_from_slice(&recovered[recovered.len() - block_size..]);
        if let Err(error) =
            self.decrypt_cbc_block(&mut recovered[..block_size], &mut chain, &mut scratch)
        {
            recovered.fill(0);
            chain.fill(0);
            scratch.fill(0);
            return Err(error);
        }

        chain.copy_from_slice(&self.iv);
        for offset in (0..recovered.len()).step_by(block_size) {
            if let Err(error) = self.decrypt_cbc_block(
                &mut recovered[offset..offset + block_size],
                &mut chain,
                &mut scratch,
            ) {
                recovered.fill(0);
                chain.fill(0);
                scratch.fill(0);
                return Err(error);
            }
        }

        let key_len = usize::from(recovered[0]);
        let invalid_length = key_len > recovered.len() - 4;
        let mut difference = 0_u8;
        for index in 0..3 {
            difference |= (!recovered[1 + index]) ^ recovered[4 + index];
        }

        if invalid_length || difference != 0 {
            recovered.fill(0);
            chain.fill(0);
            scratch.fill(0);
            return Err(Rfc3211Error::IntegrityCheckFailed);
        }

        output[..key_len].copy_from_slice(&recovered[4..4 + key_len]);
        recovered.fill(0);
        chain.fill(0);
        scratch.fill(0);
        Ok(key_len)
    }
}

impl<C, R, P> KeyWrapInit<P> for Rfc3211WrapEngine<C, R>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = Rfc3211InitError<<C as BlockCipherInit<P>>::Error>;

    fn init(&mut self, direction: WrapDirection, params: &P) -> Result<(), Self::Error> {
        let block_size = self.cipher.block_size();
        if block_size < MINIMUM_BLOCK_BYTES {
            return Err(Rfc3211InitError::UnsupportedBlockSize {
                actual: block_size,
                minimum: MINIMUM_BLOCK_BYTES,
            });
        }

        let iv = params.iv();
        if iv.len() != block_size {
            return Err(Rfc3211InitError::InvalidIvLength {
                actual: iv.len(),
                required: block_size,
            });
        }

        let cipher_direction = match direction {
            WrapDirection::Wrap => CipherDirection::Encrypt,
            WrapDirection::Unwrap => CipherDirection::Decrypt,
        };
        self.cipher
            .init(cipher_direction, params)
            .map_err(Rfc3211InitError::Cipher)?;

        self.iv.clear();
        self.iv.extend_from_slice(iv);
        self.direction = Some(direction);
        Ok(())
    }
}
