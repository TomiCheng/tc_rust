//! Noekeon block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::cipher;
use crate::{BLOCK_BYTES, KEY_BYTES};

/// Noekeon in direct-key mode, with a 16-byte key and a 16-byte block.
pub struct NoekeonEngine {
    working_key: [u32; 4],
    for_encryption: bool,
    initialised: bool,
}

impl NoekeonEngine {
    /// Creates an uninitialised Noekeon engine.
    pub const fn new() -> Self {
        Self {
            working_key: [0; 4],
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for NoekeonEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for NoekeonEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("Noekeon")
    }
}

impl BlockCipher for NoekeonEngine {
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

impl BlockCipherInit for NoekeonEngine {
    type Params<'a> = dyn KeyParams + 'a;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        let for_encryption = direction == CipherDirection::Encrypt;
        let key = params.key();
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| InitError::InvalidKeyLength(key.len()))?;

        self.working_key = cipher::prepare_key(for_encryption, key);
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }
}
