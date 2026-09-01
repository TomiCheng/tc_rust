//! RC6 block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::cipher::{self, SUBKEYS};
use crate::{BLOCK_BYTES, MAX_KEY_BYTES};

/// RC6-32/20 with a variable-length key and a 16-byte block.
pub struct Rc6Engine {
    subkeys: [u32; SUBKEYS],
    for_encryption: bool,
    initialised: bool,
}

impl Rc6Engine {
    /// Creates an uninitialised RC6 engine.
    pub const fn new() -> Self {
        Self {
            subkeys: [0; SUBKEYS],
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for Rc6Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for Rc6Engine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("RC6")
    }
}

impl BlockCipher for Rc6Engine {
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
            cipher::encrypt(&self.subkeys, input, output);
        } else {
            cipher::decrypt(&self.subkeys, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for Rc6Engine {
    type Error = InitError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        self.subkeys = cipher::expand_key(key);
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}
