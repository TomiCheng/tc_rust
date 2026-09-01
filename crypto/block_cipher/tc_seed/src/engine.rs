//! SEED block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::cipher::{self, WORKING_KEY_WORDS};
use crate::{BLOCK_BYTES, KEY_BYTES};

/// SEED with a 16-byte key and a 16-byte block.
pub struct SeedEngine {
    working_key: [u32; WORKING_KEY_WORDS],
    for_encryption: bool,
    initialised: bool,
}

impl SeedEngine {
    /// Creates an uninitialised SEED engine.
    pub const fn new() -> Self {
        Self {
            working_key: [0; WORKING_KEY_WORDS],
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for SeedEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for SeedEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("SEED")
    }
}

impl BlockCipher for SeedEngine {
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
        if self.for_encryption {
            cipher::encrypt_block(&self.working_key, input, output);
        } else {
            cipher::decrypt_block(&self.working_key, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

impl BlockCipherInit for SeedEngine {
    type Params<'a> = dyn KeyParams + 'a;
    type Error = InitError;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        let key = params.key();
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| InitError::InvalidKeyLength(key.len()))?;

        // 兩個方向共用同一份工作金鑰,只有輪次順序不同。
        self.working_key = cipher::create_working_key(key);
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}
