//! SM4 block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::cipher::{self, ROUNDS};
use crate::{BLOCK_BYTES, KEY_BYTES};

/// SM4 with a 16-byte key and a 16-byte block.
///
/// The direction is baked into the round-key order, so the engine keeps no
/// direction flag: [`init`](BlockCipherInit::init) picks the schedule and
/// [`process_block`](BlockCipher::process_block) always runs the same loop.
pub struct Sm4Engine {
    round_keys: [u32; ROUNDS],
    initialised: bool,
}

impl Sm4Engine {
    /// Creates an uninitialised SM4 engine.
    pub const fn new() -> Self {
        Self {
            round_keys: [0; ROUNDS],
            initialised: false,
        }
    }
}

impl Default for Sm4Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for Sm4Engine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("SM4")
    }
}

impl BlockCipher for Sm4Engine {
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
        cipher::process_block(&self.round_keys, input, output);
        Ok(BLOCK_BYTES)
    }
}

impl BlockCipherInit for Sm4Engine {
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

        self.round_keys = cipher::expand_key(direction == CipherDirection::Encrypt, key);
        self.initialised = true;
        Ok(())
    }
}
