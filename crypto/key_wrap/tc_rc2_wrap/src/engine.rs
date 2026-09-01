//! CMS RC2 key-wrap engine.

use rand_core::CryptoRng;
use tc_cipher::{
    BlockCipher, BlockCipherInit, CipherDirection, KeyWrap, KeyWrapInit, WrapDirection,
};
use tc_crypto::AlgorithmName;
use tc_digest::Digest;
use tc_params::{OptionalIvParams, Rc2Params};
use tc_rc2::Rc2Engine;
use tc_sha::Sha1Digest;

use crate::{Rc2WrapError, Rc2WrapInitError};

const BLOCK_BYTES: usize = 8;
const CHECKSUM_BYTES: usize = 8;
const WRAP_OVERHEAD: usize = BLOCK_BYTES + CHECKSUM_BYTES;
const MAX_KEY_BYTES: usize = u8::MAX as usize;
const MAX_WRAPPED_BYTES: usize = MAX_KEY_BYTES + 1 + WRAP_OVERHEAD;
const IV2: [u8; BLOCK_BYTES] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

/// CMS RC2 key wrapping with SHA-1 integrity and random padding.
pub struct Rc2WrapEngine<R> {
    cipher: Rc2Engine,
    sha1: Sha1Digest,
    rng: R,
    iv: [u8; BLOCK_BYTES],
    direction: Option<WrapDirection>,
}

impl<R> Rc2WrapEngine<R> {
    /// Creates an uninitialized wrapper using `rng` for IV and padding bytes.
    pub fn new(rng: R) -> Self {
        Self {
            cipher: Rc2Engine::new(),
            sha1: Sha1Digest::new(),
            rng,
            iv: [0; BLOCK_BYTES],
            direction: None,
        }
    }

    fn checksum(&mut self, input: &[u8]) -> [u8; CHECKSUM_BYTES] {
        let mut digest = [0u8; 20];
        self.sha1.update(input);
        self.sha1.do_final(&mut digest);
        let mut checksum = [0u8; CHECKSUM_BYTES];
        checksum.copy_from_slice(&digest[..CHECKSUM_BYTES]);
        digest.fill(0);
        checksum
    }

    fn encrypt_cbc(&mut self, buffer: &mut [u8], iv: &[u8; 8]) -> Result<(), Rc2WrapError> {
        let mut chain = *iv;
        let mut input = [0u8; BLOCK_BYTES];
        for block in buffer.chunks_exact_mut(BLOCK_BYTES) {
            for index in 0..BLOCK_BYTES {
                input[index] = block[index] ^ chain[index];
            }
            self.cipher
                .process_block(&input, block)
                .map_err(Rc2WrapError::Cipher)?;
            chain.copy_from_slice(block);
        }
        input.fill(0);
        chain.fill(0);
        Ok(())
    }

    fn decrypt_cbc(&mut self, buffer: &mut [u8], iv: &[u8; 8]) -> Result<(), Rc2WrapError> {
        let mut chain = *iv;
        let mut input = [0u8; BLOCK_BYTES];
        for block in buffer.chunks_exact_mut(BLOCK_BYTES) {
            input.copy_from_slice(block);
            self.cipher
                .process_block(&input, block)
                .map_err(Rc2WrapError::Cipher)?;
            for index in 0..BLOCK_BYTES {
                block[index] ^= chain[index];
            }
            chain.copy_from_slice(&input);
        }
        input.fill(0);
        chain.fill(0);
        Ok(())
    }
}

impl<R: Default> Default for Rc2WrapEngine<R> {
    fn default() -> Self {
        Self::new(R::default())
    }
}

impl<R> AlgorithmName for Rc2WrapEngine<R> {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("RC2")
    }
}

impl<R: CryptoRng> KeyWrap for Rc2WrapEngine<R> {
    type Error = Rc2WrapError;

    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if input_len > MAX_KEY_BYTES {
            return Err(Rc2WrapError::InvalidWrapLength);
        }
        let padded = input_len
            .checked_add(1)
            .ok_or(Rc2WrapError::InvalidWrapLength)?
            .div_ceil(BLOCK_BYTES)
            .checked_mul(BLOCK_BYTES)
            .ok_or(Rc2WrapError::InvalidWrapLength)?;
        padded
            .checked_add(WRAP_OVERHEAD)
            .ok_or(Rc2WrapError::InvalidWrapLength)
    }

    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if !(WRAP_OVERHEAD + BLOCK_BYTES..=MAX_WRAPPED_BYTES).contains(&input_len)
            || !input_len.is_multiple_of(BLOCK_BYTES)
        {
            return Err(Rc2WrapError::InvalidUnwrapLength);
        }
        Ok(input_len - WRAP_OVERHEAD - 1)
    }

    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Wrap) => {}
            Some(WrapDirection::Unwrap) => return Err(Rc2WrapError::NotForWrapping),
            None => return Err(Rc2WrapError::NotInitialised),
        }
        let required = self.wrapped_len(input.len())?;
        if output.len() < required {
            return Err(Rc2WrapError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let padded_end = required - CHECKSUM_BYTES;
        let buffer = &mut output[..required];
        buffer[..BLOCK_BYTES].copy_from_slice(&self.iv);
        buffer[BLOCK_BYTES] = input.len() as u8;
        buffer[BLOCK_BYTES + 1..BLOCK_BYTES + 1 + input.len()].copy_from_slice(input);
        self.rng
            .fill_bytes(&mut buffer[BLOCK_BYTES + 1 + input.len()..padded_end]);
        let mut checksum = self.checksum(&buffer[BLOCK_BYTES..padded_end]);
        buffer[padded_end..].copy_from_slice(&checksum);
        checksum.fill(0);

        let iv = self.iv;
        if let Err(error) = self.encrypt_cbc(&mut buffer[BLOCK_BYTES..], &iv) {
            buffer.fill(0);
            return Err(error);
        }
        buffer.reverse();
        if let Err(error) = self.encrypt_cbc(buffer, &IV2) {
            buffer.fill(0);
            return Err(error);
        }
        Ok(required)
    }

    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Unwrap) => {}
            Some(WrapDirection::Wrap) => return Err(Rc2WrapError::NotForUnwrapping),
            None => return Err(Rc2WrapError::NotInitialised),
        }
        let capacity = self.max_unwrapped_len(input.len())?;
        if output.len() < capacity {
            return Err(Rc2WrapError::OutputTooShort {
                required: capacity,
                available: output.len(),
            });
        }

        let mut recovered = input.to_vec();
        if let Err(error) = self.decrypt_cbc(&mut recovered, &IV2) {
            recovered.fill(0);
            return Err(error);
        }
        recovered.reverse();
        self.iv.copy_from_slice(&recovered[..BLOCK_BYTES]);
        let iv = self.iv;
        if let Err(error) = self.decrypt_cbc(&mut recovered[BLOCK_BYTES..], &iv) {
            recovered.fill(0);
            return Err(error);
        }

        let checksum_start = recovered.len() - CHECKSUM_BYTES;
        let mut expected = self.checksum(&recovered[BLOCK_BYTES..checksum_start]);
        let checksum_valid = fixed_time_eq(&expected, &recovered[checksum_start..]);
        expected.fill(0);
        let encoded_len = usize::from(recovered[BLOCK_BYTES]);
        let maximum_len = checksum_start - BLOCK_BYTES - 1;
        let length_valid = encoded_len <= maximum_len;
        let padding_len = maximum_len.saturating_sub(encoded_len);
        let padding_valid = length_valid && padding_len < BLOCK_BYTES;
        if !checksum_valid || !padding_valid {
            recovered.fill(0);
            return Err(Rc2WrapError::IntegrityCheckFailed);
        }

        let key_start = BLOCK_BYTES + 1;
        output[..encoded_len].copy_from_slice(&recovered[key_start..key_start + encoded_len]);
        recovered.fill(0);
        Ok(encoded_len)
    }
}

impl<R, P> KeyWrapInit<P> for Rc2WrapEngine<R>
where
    R: CryptoRng,
    P: Rc2Params + OptionalIvParams + ?Sized,
{
    type Error = Rc2WrapInitError;

    fn init(&mut self, direction: WrapDirection, params: &P) -> Result<(), Self::Error> {
        let cipher_direction = match direction {
            WrapDirection::Wrap => {
                self.iv = match params.optional_iv() {
                    Some(iv) => iv
                        .try_into()
                        .map_err(|_| Rc2WrapInitError::InvalidIvLength {
                            actual: iv.len(),
                            required: BLOCK_BYTES,
                        })?,
                    None => {
                        let mut iv = [0u8; BLOCK_BYTES];
                        self.rng.fill_bytes(&mut iv);
                        iv
                    }
                };
                CipherDirection::Encrypt
            }
            WrapDirection::Unwrap => {
                if params.optional_iv().is_some() {
                    return Err(Rc2WrapInitError::IvNotAllowedForUnwrap);
                }
                self.iv.fill(0);
                CipherDirection::Decrypt
            }
        };
        self.cipher
            .init(cipher_direction, params)
            .map_err(Rc2WrapInitError::Cipher)?;
        self.direction = Some(direction);
        Ok(())
    }
}

fn fixed_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}
