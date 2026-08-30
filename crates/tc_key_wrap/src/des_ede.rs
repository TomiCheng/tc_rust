//! CMS Triple-DES key wrap (RFC 3217), ported from Bouncy Castle's
//! `DesEdeWrapEngine`.

use rand_core::CryptoRng;
use tc_block_cipher::{DesEdeEngine, DesEdeParams};
use tc_block_modes::{CbcBlockCipher, CbcParams};
use tc_cipher_core::{
    BlockCipher, BlockCipherInit, CipherDirection, KeyWrap, KeyWrapInit, WrapDirection,
};
use tc_crypto_core::Digest;
use tc_digest::Sha1Digest;

use crate::WrapError;
use crate::rfc3394::fixed_time_eq;

const BLOCK_BYTES: usize = 8;
const CHECKSUM_BYTES: usize = 8;
const WRAP_OVERHEAD: usize = BLOCK_BYTES + CHECKSUM_BYTES;
const IV2: [u8; BLOCK_BYTES] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

/// Error returned by [`DesEdeWrapEngine`].
pub type DesEdeWrapError = WrapError<DesEdeEngine>;

/// Triple-DES key-encryption-key parameters and an optional wrapping IV.
///
/// Use [`Self::new`] to have the wrapper generate an IV from its `CryptoRng`,
/// or [`Self::with_iv`] for deterministic vectors and protocols that supply an
/// IV. An external IV is accepted only when initializing for wrapping because
/// wrapped data carries that IV internally.
pub struct DesEdeWrapParams {
    cbc_params: CbcParams<DesEdeParams>,
    iv: Option<[u8; BLOCK_BYTES]>,
}

impl DesEdeWrapParams {
    /// Builds parameters that generate a fresh IV when initialized for wrap.
    pub fn new(key_params: DesEdeParams) -> Self {
        Self {
            cbc_params: CbcParams::new(key_params),
            iv: None,
        }
    }

    /// Builds parameters with an explicit 8-byte wrapping IV.
    pub fn with_iv(key_params: DesEdeParams, iv: [u8; BLOCK_BYTES]) -> Self {
        Self {
            cbc_params: CbcParams::with_iv(key_params, &iv),
            iv: Some(iv),
        }
    }
}

impl core::fmt::Debug for DesEdeWrapParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DesEdeWrapParams")
            .field("iv_supplied", &self.iv.is_some())
            .finish()
    }
}

/// CMS Triple-DES key wrapper using CBC, a SHA-1 checksum, and caller-supplied
/// cryptographically secure randomness.
pub struct DesEdeWrapEngine<R: CryptoRng> {
    engine: CbcBlockCipher<DesEdeEngine>,
    sha1: Sha1Digest,
    rng: R,
    iv: [u8; BLOCK_BYTES],
    direction: Option<WrapDirection>,
}

impl<R: CryptoRng> DesEdeWrapEngine<R> {
    /// Creates a Triple-DES key wrapper using `rng` to generate wrapping IVs.
    pub fn new(rng: R) -> Self {
        Self {
            engine: CbcBlockCipher::new(DesEdeEngine::new()),
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

    fn crypt_blocks(&mut self, buffer: &mut [u8]) -> Result<(), DesEdeWrapError> {
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

impl<R: CryptoRng + Default> Default for DesEdeWrapEngine<R> {
    fn default() -> Self {
        Self::new(R::default())
    }
}

impl<R: CryptoRng> KeyWrap for DesEdeWrapEngine<R> {
    type Error = DesEdeWrapError;

    fn algorithm_name(&self) -> &str {
        "DESede"
    }

    fn wrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if !input_len.is_multiple_of(BLOCK_BYTES) {
            return Err(WrapError::WrapDataLength);
        }
        input_len
            .checked_add(WRAP_OVERHEAD)
            .ok_or(WrapError::WrapDataLength)
    }

    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        if input_len < WRAP_OVERHEAD || !input_len.is_multiple_of(BLOCK_BYTES) {
            return Err(WrapError::UnwrapDataLength);
        }
        Ok(input_len - WRAP_OVERHEAD)
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

        let mut checksum = self.checksum(input);
        let buffer = &mut output[..required];
        buffer[..BLOCK_BYTES].copy_from_slice(&self.iv);
        buffer[BLOCK_BYTES..BLOCK_BYTES + input.len()].copy_from_slice(input);
        buffer[BLOCK_BYTES + input.len()..].copy_from_slice(&checksum);
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

        let required = self.max_unwrapped_len(input.len())?;
        if output.len() < required {
            return Err(WrapError::OutputBufferTooShort {
                required,
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

        let key_start = BLOCK_BYTES;
        let checksum_start = key_start + required;
        let mut expected_checksum = self.checksum(&temp[key_start..checksum_start]);
        let checksum_valid = fixed_time_eq(&expected_checksum, &temp[checksum_start..]);
        expected_checksum.fill(0);
        if !checksum_valid {
            temp.fill(0);
            return Err(WrapError::IntegrityCheckFailed);
        }

        output[..required].copy_from_slice(&temp[key_start..checksum_start]);
        temp.fill(0);
        Ok(required)
    }
}

impl<R: CryptoRng> KeyWrapInit for DesEdeWrapEngine<R> {
    type Params<'a> = DesEdeWrapParams;

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
