//! Camellia block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::{BLOCK_BYTES, cipher};

/// Camellia using four 256-entry `u32` T-tables.
pub struct CamelliaEngine {
    schedule: cipher::CamelliaKeySchedule,
    initialised: bool,
}

impl CamelliaEngine {
    /// Creates an uninitialised Camellia engine.
    pub const fn new() -> Self {
        Self {
            schedule: cipher::CamelliaKeySchedule::new(),
            initialised: false,
        }
    }
}

impl Default for CamelliaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for CamelliaEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("Camellia")
    }
}

impl BlockCipher for CamelliaEngine {
    type Error = BlockError;

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
        self.schedule.process_block(input, output);
        Ok(BLOCK_BYTES)
    }
}

impl BlockCipherInit for CamelliaEngine {
    type Params<'a> = dyn KeyParams + 'a;
    type Error = InitError;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        let key = params.key();
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        self.schedule
            .set_key(direction == CipherDirection::Encrypt, key);
        self.initialised = true;
        Ok(())
    }
}
