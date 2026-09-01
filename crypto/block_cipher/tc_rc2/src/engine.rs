//! RC2 block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::Rc2Params;

use crate::cipher::{self, SUBKEYS};
use crate::{BLOCK_BYTES, MAX_EFFECTIVE_KEY_BITS, MAX_KEY_BYTES};

/// RC2 with a variable-length key and an 8-byte block.
pub struct Rc2Engine {
    working_key: [u16; SUBKEYS],
    direction: CipherDirection,
    initialised: bool,
}

impl Rc2Engine {
    /// Creates an uninitialised RC2 engine.
    pub const fn new() -> Self {
        Self {
            working_key: [0; SUBKEYS],
            direction: CipherDirection::Encrypt,
            initialised: false,
        }
    }
}

impl Default for Rc2Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for Rc2Engine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("RC2")
    }
}

impl BlockCipher for Rc2Engine {
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
        match self.direction {
            CipherDirection::Encrypt => cipher::encrypt(&self.working_key, input, output),
            CipherDirection::Decrypt => cipher::decrypt(&self.working_key, input, output),
        }
        Ok(BLOCK_BYTES)
    }
}

impl BlockCipherInit for Rc2Engine {
    type Params<'a> = dyn Rc2Params + 'a;
    type Error = InitError;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        let key = params.key();
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        let effective_key_bits = params.effective_key_bits();
        if effective_key_bits == 0 || effective_key_bits > MAX_EFFECTIVE_KEY_BITS {
            return Err(InitError::InvalidEffectiveKeyBits(effective_key_bits));
        }

        self.working_key = cipher::expand_key(key, effective_key_bits);
        self.direction = direction;
        self.initialised = true;
        Ok(())
    }
}
