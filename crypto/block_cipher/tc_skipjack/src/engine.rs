//! SKIPJACK block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::cipher::{self, Schedule};
use crate::{BLOCK_BYTES, KEY_BYTES};

/// SKIPJACK with a 10-byte key and an 8-byte block.
pub struct SkipjackEngine {
    schedule: Schedule,
    for_encryption: bool,
    initialised: bool,
}

impl SkipjackEngine {
    /// Creates an uninitialised SKIPJACK engine.
    pub const fn new() -> Self {
        Self {
            schedule: [[0; 4]; cipher::STEPS],
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for SkipjackEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for SkipjackEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("SKIPJACK")
    }
}

impl BlockCipher for SkipjackEngine {
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
            cipher::encrypt_block(&self.schedule, input, output);
        } else {
            cipher::decrypt_block(&self.schedule, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for SkipjackEngine {
    type Error = InitError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| InitError::InvalidKeyLength(key.len()))?;

        // 兩個方向共用同一份展開金鑰,差別在步數方向與 G/H 的選擇。
        self.schedule = cipher::expand_key(key);
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}
