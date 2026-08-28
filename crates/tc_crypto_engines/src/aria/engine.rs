//! ARIA block-cipher engine.

use tc_crypto_core::BlockCipher;

use super::{ARIA_BLOCK_BYTES, BlockCipherError, AriaParams, AriaRoundKeys, cipher};

/// Portable ARIA-128, ARIA-192, and ARIA-256 block cipher.
pub struct AriaEngine {
    round_keys: AriaRoundKeys,
    rounds: usize,
    initialised: bool,
}

impl AriaEngine {
    /// Creates an uninitialised ARIA engine.
    pub const fn new() -> Self {
        Self {
            round_keys: [[0; ARIA_BLOCK_BYTES]; 17],
            rounds: 0,
            initialised: false,
        }
    }
}

impl Default for AriaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for AriaEngine {
    type Params<'a> = AriaParams;
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "ARIA"
    }

    fn block_size(&self) -> usize {
        ARIA_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        (self.round_keys, self.rounds) = cipher::key_schedule(for_encryption, params.key());
        self.initialised = true;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherError::NotInitialised);
        }
        if input.len() < ARIA_BLOCK_BYTES || output.len() < ARIA_BLOCK_BYTES {
            return Err(BlockCipherError::BufferTooShort);
        }

        let input: &[u8; ARIA_BLOCK_BYTES] = input[..ARIA_BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; ARIA_BLOCK_BYTES] =
            (&mut output[..ARIA_BLOCK_BYTES]).try_into().unwrap();
        cipher::process_block(&self.round_keys, self.rounds, input, output);
        Ok(ARIA_BLOCK_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_processing_errors() {
        let mut engine = AriaEngine::new();
        assert_eq!(engine.algorithm_name(), "ARIA");
        assert_eq!(engine.block_size(), ARIA_BLOCK_BYTES);
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 16]),
            Err(BlockCipherError::NotInitialised)
        );

        engine
            .init(true, &AriaParams::new(&[0u8; 16]).unwrap())
            .unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 15], &mut [0u8; 16]),
            Err(BlockCipherError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 15]),
            Err(BlockCipherError::BufferTooShort)
        );
    }
}
