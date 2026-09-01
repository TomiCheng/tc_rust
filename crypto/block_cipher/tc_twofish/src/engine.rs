//! Twofish block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::cipher::{self, KeySchedule};
use crate::{BLOCK_BYTES, KEY_BYTES};

/// Twofish with a 16-byte block and a 16-, 24-, or 32-byte key.
pub struct TwofishEngine {
    schedule: KeySchedule,
    for_encryption: bool,
    initialised: bool,
}

impl TwofishEngine {
    /// Creates an uninitialised Twofish engine.
    pub const fn new() -> Self {
        Self {
            schedule: KeySchedule::new(),
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for TwofishEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for TwofishEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("Twofish")
    }
}

impl BlockCipher for TwofishEngine {
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }
        if input.len() < BLOCK_BYTES || output.len() < BLOCK_BYTES {
            return Err(BlockError::BufferTooShort);
        }

        let input: &[u8; BLOCK_BYTES] = input[..BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; BLOCK_BYTES] = (&mut output[..BLOCK_BYTES]).try_into().unwrap();
        if self.for_encryption {
            cipher::encrypt_block(&self.schedule, input, output);
        } else {
            cipher::decrypt_block(&self.schedule, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

impl BlockCipherInit for TwofishEngine {
    type Params<'a> = dyn KeyParams + 'a;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        let key = params.key();
        if !KEY_BYTES.contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        self.schedule = cipher::expand_key(key);
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}
