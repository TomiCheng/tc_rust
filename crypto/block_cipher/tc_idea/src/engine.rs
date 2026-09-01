//! IDEA block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::cipher::{self, SUBKEY_WORDS};
use crate::{BLOCK_BYTES, KEY_BYTES};

/// IDEA with a 16-byte key and an 8-byte block.
///
/// The direction is baked into the subkey schedule, so the engine keeps no
/// direction flag of its own: [`init`](BlockCipherInit::init) selects the
/// schedule and [`process_block`](BlockCipher::process_block) always runs the
/// same round function.
pub struct IdeaEngine {
    working_key: [u16; SUBKEY_WORDS],
    initialised: bool,
}

impl IdeaEngine {
    /// Creates an uninitialised IDEA engine.
    pub const fn new() -> Self {
        Self {
            working_key: [0; SUBKEY_WORDS],
            initialised: false,
        }
    }
}

impl Default for IdeaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for IdeaEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("IDEA")
    }
}

impl BlockCipher for IdeaEngine {
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
        cipher::process_block(&self.working_key, input, output);
        Ok(BLOCK_BYTES)
    }
}

impl BlockCipherInit for IdeaEngine {
    type Params<'a> = dyn KeyParams + 'a;
    type Error = InitError;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        let key = params.key();
        // bc 會把過短的金鑰左補零、過長的只取前十六位元組;此處要求剛好 128 位元。
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| InitError::InvalidKeyLength(key.len()))?;
        self.working_key = cipher::generate_working_key(direction == CipherDirection::Encrypt, key);
        self.initialised = true;
        Ok(())
    }
}
