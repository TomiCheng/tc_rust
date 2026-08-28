//! Blowfish block-cipher engine.

use tc_crypto_core::BlockCipher;

use super::{BLOWFISH_BLOCK_BYTES, BlowfishError, BlowfishParams, cipher};

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

impl BlockCipher for BlowfishEngine {
    type Params<'a> = BlowfishParams;
    type Error = BlowfishError;

    fn algorithm_name(&self) -> &str {
        "Blowfish"
    }

    fn block_size(&self) -> usize {
        BLOWFISH_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.state.expand_key(params.key());
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlowfishError::NotInitialised);
        }
        if input.len() < BLOWFISH_BLOCK_BYTES || output.len() < BLOWFISH_BLOCK_BYTES {
            return Err(BlowfishError::BufferTooShort);
        }

        let input: &[u8; BLOWFISH_BLOCK_BYTES] = input[..BLOWFISH_BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; BLOWFISH_BLOCK_BYTES] =
            (&mut output[..BLOWFISH_BLOCK_BYTES]).try_into().unwrap();
        if self.for_encryption {
            self.state.encrypt_block(input, output);
        } else {
            self.state.decrypt_block(input, output);
        }
        Ok(BLOWFISH_BLOCK_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_processing_errors() {
        let mut engine = BlowfishEngine::new();
        assert_eq!(engine.algorithm_name(), "Blowfish");
        assert_eq!(engine.block_size(), BLOWFISH_BLOCK_BYTES);
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 8]),
            Err(BlowfishError::NotInitialised)
        );

        engine
            .init(true, &BlowfishParams::new(&[0u8; 4]).unwrap())
            .unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 7], &mut [0u8; 8]),
            Err(BlowfishError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 7]),
            Err(BlowfishError::BufferTooShort)
        );
    }
}
