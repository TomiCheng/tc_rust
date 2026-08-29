//! Camellia block-cipher engine.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::{BlockCipherError, CAMELLIA_BLOCK_BYTES, CamelliaParams, cipher};

/// Camellia using four 256-entry `u32` T-tables.
pub struct CamelliaEngine {
    schedule: cipher::CamelliaKeySchedule,
    initialised: bool,
}

impl CamelliaEngine {
    /// Creates an uninitialised Camellia engine.
    pub const fn new() -> Self {
        Self {
            schedule: cipher::CamelliaKeySchedule::new(),
            initialised: false,
        }
    }
}

impl Default for CamelliaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for CamelliaEngine {
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "Camellia"
    }

    fn block_size(&self) -> usize {
        CAMELLIA_BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherError::NotInitialised);
        }
        if input.len() < CAMELLIA_BLOCK_BYTES || output.len() < CAMELLIA_BLOCK_BYTES {
            return Err(BlockCipherError::BufferTooShort);
        }

        let input: &[u8; CAMELLIA_BLOCK_BYTES] = input[..CAMELLIA_BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; CAMELLIA_BLOCK_BYTES] =
            (&mut output[..CAMELLIA_BLOCK_BYTES]).try_into().unwrap();
        self.schedule.process_block(input, output);
        Ok(CAMELLIA_BLOCK_BYTES)
    }
}

impl BlockCipherInit for CamelliaEngine {
    type Params<'a> = CamelliaParams;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.schedule
            .set_key(direction == CipherDirection::Encrypt, params.key());
        self.initialised = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_processing_errors() {
        let mut engine = CamelliaEngine::new();
        assert_eq!(engine.algorithm_name(), "Camellia");
        assert_eq!(engine.block_size(), CAMELLIA_BLOCK_BYTES);
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 16]),
            Err(BlockCipherError::NotInitialised)
        );

        engine
            .init(
                CipherDirection::Encrypt,
                &CamelliaParams::new(&[0u8; 16]).unwrap(),
            )
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
