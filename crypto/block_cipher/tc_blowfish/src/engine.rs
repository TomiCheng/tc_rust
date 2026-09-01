//! Blowfish block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::{BLOCK_BYTES, MAX_KEY_BYTES, MIN_KEY_BYTES, cipher};

/// Portable Blowfish block cipher.
pub struct BlowfishEngine {
    state: cipher::BlowfishState,
    for_encryption: bool,
    initialised: bool,
}

impl BlowfishEngine {
    /// Creates an uninitialised Blowfish engine.
    pub const fn new() -> Self {
        Self {
            state: cipher::BlowfishState::new(),
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for BlowfishEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for BlowfishEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("Blowfish")
    }
}

impl BlockCipher for BlowfishEngine {
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
            self.state.encrypt_block(input, output);
        } else {
            self.state.decrypt_block(input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for BlowfishEngine {
    type Error = InitError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !(MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        self.state.expand_key(key);
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}
