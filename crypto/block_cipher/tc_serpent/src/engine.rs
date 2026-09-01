//! Serpent and Tnepres block-cipher engines over the shared round core.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::cipher::{self, Representation, WORKING_KEY_WORDS};
use crate::{BLOCK_BYTES, KEY_STEP_BYTES, MAX_KEY_BYTES, MIN_KEY_BYTES};

/// The state both engines share; only the [`Representation`] differs.
struct EngineState {
    working_key: [u32; WORKING_KEY_WORDS],
    for_encryption: bool,
    initialised: bool,
}

impl EngineState {
    const fn new() -> Self {
        Self {
            working_key: [0; WORKING_KEY_WORDS],
            for_encryption: false,
            initialised: false,
        }
    }

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &(dyn KeyParams + '_),
        representation: Representation,
    ) -> Result<(), InitError> {
        let key = params.key();
        if !(MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&key.len())
            || !key.len().is_multiple_of(KEY_STEP_BYTES)
        {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        self.working_key = cipher::expand_key(key, representation);
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }

    fn process_block(
        &self,
        input: &[u8],
        output: &mut [u8],
        representation: Representation,
    ) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }
        if input.len() < BLOCK_BYTES || output.len() < BLOCK_BYTES {
            return Err(BlockError::BufferTooShort);
        }

        let input: &[u8; BLOCK_BYTES] = input[..BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; BLOCK_BYTES] = (&mut output[..BLOCK_BYTES]).try_into().unwrap();
        if self.for_encryption {
            cipher::encrypt_block(&self.working_key, representation, input, output);
        } else {
            cipher::decrypt_block(&self.working_key, representation, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

/// Serpent in the conventional representation.
pub struct SerpentEngine {
    state: EngineState,
}

impl SerpentEngine {
    /// Creates an uninitialised Serpent engine.
    pub const fn new() -> Self {
        Self {
            state: EngineState::new(),
        }
    }
}

impl Default for SerpentEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for SerpentEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("Serpent")
    }
}

impl BlockCipher for SerpentEngine {
    type Error = BlockError;

    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        self.state
            .process_block(input, output, Representation::Serpent)
    }
}

impl BlockCipherInit for SerpentEngine {
    type Params<'a> = dyn KeyParams + 'a;
    type Error = InitError;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        self.state.init(direction, params, Representation::Serpent)
    }
}

/// Serpent in the byte- and word-reversed representation of the AES submission.
///
/// Tnepres is not a drop-in replacement for [`SerpentEngine`]: the same key and
/// block bytes produce different ciphertext.
pub struct TnepresEngine {
    state: EngineState,
}

impl TnepresEngine {
    /// Creates an uninitialised Tnepres engine.
    pub const fn new() -> Self {
        Self {
            state: EngineState::new(),
        }
    }
}

impl Default for TnepresEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for TnepresEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("Tnepres")
    }
}

impl BlockCipher for TnepresEngine {
    type Error = BlockError;

    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        self.state
            .process_block(input, output, Representation::Tnepres)
    }
}

impl BlockCipherInit for TnepresEngine {
    type Params<'a> = dyn KeyParams + 'a;
    type Error = InitError;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        self.state.init(direction, params, Representation::Tnepres)
    }
}
