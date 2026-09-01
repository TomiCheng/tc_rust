//! ARIA block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::{BLOCK_BYTES, RoundKeys, cipher};

/// Portable ARIA-128, ARIA-192, and ARIA-256 block cipher.
pub struct AriaEngine {
    round_keys: RoundKeys,
    rounds: usize,
    initialised: bool,
}

impl AriaEngine {
    /// Creates an uninitialised ARIA engine.
    pub const fn new() -> Self {
        Self {
            round_keys: [[0; BLOCK_BYTES]; 17],
            rounds: 0,
            initialised: false,
        }
    }
}

impl Default for AriaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for AriaEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("ARIA")
    }
}

impl BlockCipher for AriaEngine {
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
        cipher::process_block(&self.round_keys, self.rounds, input, output);
        Ok(BLOCK_BYTES)
    }
}

impl BlockCipherInit for AriaEngine {
    type Params<'a> = dyn KeyParams + 'a;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        let key = params.key();
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        let for_encryption = direction == CipherDirection::Encrypt;
        (self.round_keys, self.rounds) = cipher::key_schedule(for_encryption, key);
        self.initialised = true;
        Ok(())
    }
}
