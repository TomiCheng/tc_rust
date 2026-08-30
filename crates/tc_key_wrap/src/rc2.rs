//! CMS RC2 key wrap (RFC 3217), ported from Bouncy Castle's `RC2WrapEngine`.

use alloc::vec;
use alloc::vec::Vec;
use rand_core::CryptoRng;
use tc_block_cipher::{Rc2Engine, Rc2Params};
use tc_block_modes::{CbcBlockCipher, CbcParams};
use tc_cipher_core::{
    BlockCipher, BlockCipherInit, CipherDirection, KeyWrap, KeyWrapInit, WrapDirection,
};
use tc_crypto_core::{Digest, Wrapper};
use tc_digest::Sha1Digest;

use crate::WrapError;
use crate::rfc3394::fixed_time_eq;

const BLOCK_BYTES: usize = 8;
const CHECKSUM_BYTES: usize = 8;
const WRAP_OVERHEAD: usize = BLOCK_BYTES + CHECKSUM_BYTES;
const MAX_KEY_BYTES: usize = u8::MAX as usize;
const MAX_WRAPPED_BYTES: usize = MAX_KEY_BYTES + 1 + WRAP_OVERHEAD;
const IV2: [u8; BLOCK_BYTES] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

/// Error returned by [`Rc2WrapEngine`].
pub type Rc2WrapError = WrapError<Rc2Engine>;

/// RC2 key-encryption-key parameters and an optional wrapping IV.
///
/// The supplied [`Rc2Params`] retains its effective-key-bits setting. Use
/// [`Self::new`] to have the wrapper generate an IV from its `CryptoRng`, or
/// [`Self::with_iv`] for deterministic vectors and protocols that supply an
/// IV. An external IV is accepted only when initializing for wrapping because
/// wrapped data carries that IV internally.
pub struct Rc2WrapParams {
    cbc_params: CbcParams<Rc2Params>,
    iv: Option<[u8; BLOCK_BYTES]>,
}

impl Rc2WrapParams {
    /// Builds parameters that generate a fresh IV when initialized for wrap.
    pub fn new(key_params: Rc2Params) -> Self {
        Self {
            cbc_params: CbcParams::new(key_params),
            iv: None,
        }
    }

    /// Builds parameters with an explicit 8-byte wrapping IV.
    pub fn with_iv(key_params: Rc2Params, iv: [u8; BLOCK_BYTES]) -> Self {
        Self {
            cbc_params: CbcParams::with_iv(key_params, &iv),
            iv: Some(iv),
        }
    }
}

impl core::fmt::Debug for Rc2WrapParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rc2WrapParams")
            .field("iv_supplied", &self.iv.is_some())
            .finish()
    }
}

/// CMS RC2 key wrapper using CBC, a SHA-1 checksum, and caller-supplied
/// cryptographically secure randomness.
pub struct Rc2WrapEngine<R: CryptoRng> {
    engine: CbcBlockCipher<Rc2Engine>,
    sha1: Sha1Digest,
    rng: R,
    iv: [u8; BLOCK_BYTES],
    direction: Option<WrapDirection>,
}

impl<R: CryptoRng> Rc2WrapEngine<R> {
    /// Creates an RC2 key wrapper using `rng` for IV and padding generation.
    pub fn new(rng: R) -> Self {
        Self {
            engine: CbcBlockCipher::new(Rc2Engine::new()),
            sha1: Sha1Digest::new(),
            rng,
            iv: [0_u8; BLOCK_BYTES],
            direction: None,
        }
    }

    fn checksum(&mut self, input: &[u8]) -> [u8; CHECKSUM_BYTES] {
        let mut digest = [0_u8; 20];
        self.sha1.update(input);
        self.sha1.do_final(&mut digest);

        let mut checksum = [0_u8; CHECKSUM_BYTES];
        checksum.copy_from_slice(&digest[..CHECKSUM_BYTES]);
        digest.fill(0);
        checksum
    }

    fn crypt_blocks(&mut self, buffer: &mut [u8]) -> Result<(), Rc2WrapError> {
        debug_assert!(buffer.len().is_multiple_of(BLOCK_BYTES));

        let mut input_block = [0_u8; BLOCK_BYTES];
        for output_block in buffer.chunks_exact_mut(BLOCK_BYTES) {
            input_block.copy_from_slice(output_block);
            if let Err(error) = self.engine.process_block(&input_block, output_block) {
                input_block.fill(0);
                return Err(WrapError::BlockCipherMode(error));
            }
        }
        input_block.fill(0);
        Ok(())
    }
}

impl<R: CryptoRng + Default> Default for Rc2WrapEngine<R> {
    fn default() -> Self {
        Self::new(R::default())
    }
}

impl<R: CryptoRng> KeyWrap for Rc2WrapEngine<R> {
    type Error = Rc2WrapError;

    fn algorithm_name(&self) -> &str {
        "RC2"
    }

    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if input_len > MAX_KEY_BYTES {
            return Err(WrapError::WrapDataLength);
        }

        let length_and_key = input_len.checked_add(1).ok_or(WrapError::WrapDataLength)?;
        let padded_len = length_and_key
            .div_ceil(BLOCK_BYTES)
            .checked_mul(BLOCK_BYTES)
            .ok_or(WrapError::WrapDataLength)?;
        padded_len
            .checked_add(WRAP_OVERHEAD)
            .ok_or(WrapError::WrapDataLength)
    }

    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        let minimum_len = WRAP_OVERHEAD + BLOCK_BYTES;
        if input_len < minimum_len
            || input_len > MAX_WRAPPED_BYTES
            || !input_len.is_multiple_of(BLOCK_BYTES)
        {
            return Err(WrapError::UnwrapDataLength);
        }

        Ok(input_len - WRAP_OVERHEAD - 1)
    }

    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Wrap) => {}
            Some(WrapDirection::Unwrap) => return Err(WrapError::NotForWrapping),
            None => return Err(WrapError::Uninitialised),
        }

        let required = self.wrapped_len(input.len())?;
        if output.len() < required {
            return Err(WrapError::OutputBufferTooShort {
                required,
                available: output.len(),
            });
        }

        let padded_len = required - WRAP_OVERHEAD;
        let lcekpad_start = BLOCK_BYTES;
        let lcekpad_end = lcekpad_start + padded_len;
        let buffer = &mut output[..required];
        buffer[..BLOCK_BYTES].copy_from_slice(&self.iv);
        buffer[lcekpad_start] = input.len() as u8;
        buffer[lcekpad_start + 1..lcekpad_start + 1 + input.len()].copy_from_slice(input);
        self.rng
            .fill_bytes(&mut buffer[lcekpad_start + 1 + input.len()..lcekpad_end]);

        let mut checksum = self.checksum(&buffer[lcekpad_start..lcekpad_end]);
        buffer[lcekpad_end..].copy_from_slice(&checksum);
        checksum.fill(0);

        self.engine
            .reset_with_iv(&self.iv)
            .map_err(WrapError::BlockCipherMode)?;
        if let Err(error) = self.crypt_blocks(&mut buffer[BLOCK_BYTES..]) {
            buffer.fill(0);
            return Err(error);
        }

        buffer.reverse();
        self.engine
            .reset_with_iv(&IV2)
            .map_err(WrapError::BlockCipherMode)?;
        if let Err(error) = self.crypt_blocks(buffer) {
            buffer.fill(0);
            return Err(error);
        }

        Ok(required)
    }

    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        match self.direction {
            Some(WrapDirection::Unwrap) => {}
            Some(WrapDirection::Wrap) => return Err(WrapError::NotForUnwrapping),
            None => return Err(WrapError::Uninitialised),
        }

        let capacity = self.max_unwrapped_len(input.len())?;
        if output.len() < capacity {
            return Err(WrapError::OutputBufferTooShort {
                required: capacity,
                available: output.len(),
            });
        }

        let mut temp = input.to_vec();
        self.engine
            .reset_with_iv(&IV2)
            .map_err(WrapError::BlockCipherMode)?;
        if let Err(error) = self.crypt_blocks(&mut temp) {
            temp.fill(0);
            return Err(error);
        }
        temp.reverse();

        self.iv.copy_from_slice(&temp[..BLOCK_BYTES]);
        self.engine
            .reset_with_iv(&self.iv)
            .map_err(WrapError::BlockCipherMode)?;
        if let Err(error) = self.crypt_blocks(&mut temp[BLOCK_BYTES..]) {
            temp.fill(0);
            return Err(error);
        }

        let lcekpad_start = BLOCK_BYTES;
        let checksum_start = temp.len() - CHECKSUM_BYTES;
        let mut expected_checksum = self.checksum(&temp[lcekpad_start..checksum_start]);
        let checksum_valid = fixed_time_eq(&expected_checksum, &temp[checksum_start..]);
        expected_checksum.fill(0);

        let lcekpad_len = checksum_start - lcekpad_start;
        let key_len = usize::from(temp[lcekpad_start]);
        let maximum_key_len = lcekpad_len - 1;
        let length_valid = key_len <= maximum_key_len;
        let padding_len = maximum_key_len.saturating_sub(key_len);
        let padding_valid = length_valid && padding_len < BLOCK_BYTES;
        if !checksum_valid || !padding_valid {
            temp.fill(0);
            return Err(WrapError::IntegrityCheckFailed);
        }

        let key_start = lcekpad_start + 1;
        output[..key_len].copy_from_slice(&temp[key_start..key_start + key_len]);
        temp.fill(0);
        Ok(key_len)
    }
}

impl<R: CryptoRng> KeyWrapInit for Rc2WrapEngine<R> {
    type Params<'a> = Rc2WrapParams;

    fn init(
        &mut self,
        direction: WrapDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        let cipher_direction = match direction {
            WrapDirection::Wrap => {
                self.iv = match params.iv {
                    Some(iv) => iv,
                    None => {
                        let mut iv = [0_u8; BLOCK_BYTES];
                        self.rng.fill_bytes(&mut iv);
                        iv
                    }
                };
                CipherDirection::Encrypt
            }
            WrapDirection::Unwrap => {
                if params.iv.is_some() {
                    return Err(WrapError::IvNotAllowedForUnwrap);
                }
                self.iv.fill(0);
                CipherDirection::Decrypt
            }
        };

        self.engine
            .init(cipher_direction, &params.cbc_params)
            .map_err(WrapError::BlockCipherMode)?;
        let initial_iv = match direction {
            WrapDirection::Wrap => &self.iv,
            WrapDirection::Unwrap => &IV2,
        };
        self.engine
            .reset_with_iv(initial_iv)
            .map_err(WrapError::BlockCipherMode)?;
        self.direction = Some(direction);
        Ok(())
    }
}

impl<R: CryptoRng> Wrapper for Rc2WrapEngine<R> {
    type Params<'a> = Rc2WrapParams;
    type Error = Rc2WrapError;

    fn algorithm_name(&self) -> &str {
        KeyWrap::algorithm_name(self)
    }

    fn init(&mut self, for_wrapping: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        let direction = if for_wrapping {
            WrapDirection::Wrap
        } else {
            WrapDirection::Unwrap
        };
        KeyWrapInit::init(self, direction, params)
    }

    fn wrap(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let required = KeyWrap::wrapped_len(self, input.len())?;
        let mut output = vec![0_u8; required];
        let written = KeyWrap::wrap_into(self, input, &mut output)?;
        debug_assert_eq!(written, required);
        Ok(output)
    }

    fn unwrap(&mut self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let capacity = KeyWrap::max_unwrapped_len(self, input.len())?;
        let mut output = vec![0_u8; capacity];
        let written = KeyWrap::unwrap_into(self, input, &mut output)?;
        output.truncate(written);
        Ok(output)
    }
}
