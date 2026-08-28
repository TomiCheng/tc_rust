//! Public Serpent and Tnepres engines over the shared round core.

use tc_crypto_core::BlockCipher;

use super::cipher::{Representation, WORKING_KEY_WORDS, decrypt, encrypt, expand_key};
use super::{SERPENT_BLOCK_BYTES, SerpentError, SerpentParams};

struct EngineState {
    encrypting: bool,
    working_key: Option<[u32; WORKING_KEY_WORDS]>,
}

impl EngineState {
    const fn new() -> Self {
        Self {
            encrypting: false,
            working_key: None,
        }
    }

    fn init(&mut self, encrypting: bool, params: &SerpentParams, representation: Representation) {
        self.working_key = Some(expand_key(params.key(), representation));
        self.encrypting = encrypting;
    }

    fn process(
        &self,
        input: &[u8],
        output: &mut [u8],
        representation: Representation,
    ) -> Result<usize, SerpentError> {
        let working_key = self
            .working_key
            .as_ref()
            .ok_or(SerpentError::NotInitialised)?;
        if input.len() < SERPENT_BLOCK_BYTES || output.len() < SERPENT_BLOCK_BYTES {
            return Err(SerpentError::BufferTooShort);
        }

        let state = read_state(input, representation);
        let state = if self.encrypting {
            encrypt(state, working_key)
        } else {
            decrypt(state, working_key)
        };
        write_state(output, state, representation);
        Ok(SERPENT_BLOCK_BYTES)
    }
}

/// The conventional Serpent representation used by Bouncy Castle.
pub struct SerpentEngine {
    state: EngineState,
}

impl SerpentEngine {
    /// Creates an uninitialised engine.
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

impl BlockCipher for SerpentEngine {
    type Params<'a> = SerpentParams;
    type Error = SerpentError;

    fn algorithm_name(&self) -> &str {
        "Serpent"
    }

    fn block_size(&self) -> usize {
        SERPENT_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.state
            .init(for_encryption, params, Representation::Serpent);
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.state.process(input, output, Representation::Serpent)
    }
}

/// The byte/word-reversed Serpent representation from the AES submission.
pub struct TnepresEngine {
    state: EngineState,
}

impl TnepresEngine {
    /// Creates an uninitialised engine.
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

impl BlockCipher for TnepresEngine {
    type Params<'a> = SerpentParams;
    type Error = SerpentError;

    fn algorithm_name(&self) -> &str {
        "Tnepres"
    }

    fn block_size(&self) -> usize {
        SERPENT_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.state
            .init(for_encryption, params, Representation::Tnepres);
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.state.process(input, output, Representation::Tnepres)
    }
}

fn read_state(input: &[u8], representation: Representation) -> [u32; 4] {
    match representation {
        Representation::Serpent => [
            read_le(input, 0),
            read_le(input, 4),
            read_le(input, 8),
            read_le(input, 12),
        ],
        Representation::Tnepres => [
            read_be(input, 12),
            read_be(input, 8),
            read_be(input, 4),
            read_be(input, 0),
        ],
    }
}

fn write_state(output: &mut [u8], state: [u32; 4], representation: Representation) {
    match representation {
        Representation::Serpent => {
            write_le(output, 0, state[0]);
            write_le(output, 4, state[1]);
            write_le(output, 8, state[2]);
            write_le(output, 12, state[3]);
        }
        Representation::Tnepres => {
            write_be(output, 0, state[3]);
            write_be(output, 4, state[2]);
            write_be(output, 8, state[1]);
            write_be(output, 12, state[0]);
        }
    }
}

fn read_le(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap())
}

fn read_be(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(input[offset..offset + 4].try_into().unwrap())
}

fn write_le(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_be(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_pre_init_errors() {
        let mut serpent = SerpentEngine::new();
        let mut tnepres = TnepresEngine::new();
        assert_eq!(serpent.algorithm_name(), "Serpent");
        assert_eq!(tnepres.algorithm_name(), "Tnepres");
        assert_eq!(serpent.block_size(), SERPENT_BLOCK_BYTES);
        assert_eq!(tnepres.block_size(), SERPENT_BLOCK_BYTES);
        assert_eq!(
            serpent.process_block(&[0u8; 16], &mut [0u8; 16]),
            Err(SerpentError::NotInitialised)
        );
        assert_eq!(
            tnepres.process_block(&[0u8; 16], &mut [0u8; 16]),
            Err(SerpentError::NotInitialised)
        );
    }

    #[test]
    fn short_buffers_are_rejected() {
        let params = SerpentParams::new(&[0u8; 16]).unwrap();
        let mut engine = SerpentEngine::new();
        engine.init(true, &params).unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 15], &mut [0u8; 16]),
            Err(SerpentError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 15]),
            Err(SerpentError::BufferTooShort)
        );
    }
}
