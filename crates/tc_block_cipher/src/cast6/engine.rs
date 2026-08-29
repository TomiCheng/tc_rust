//! CAST6 block-cipher engine.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::{BlockCipherError, CAST6_BLOCK_BYTES, Cast6Params, cipher};

/// Portable CAST6 (CAST-256) block cipher.
pub struct Cast6Engine {
    schedule: cipher::Cast6KeySchedule,
    for_encryption: bool,
    initialised: bool,
}

impl Cast6Engine {
    /// Creates an uninitialised CAST6 engine.
    pub const fn new() -> Self {
        Self {
            schedule: cipher::Cast6KeySchedule::new(),
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for Cast6Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for Cast6Engine {
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "CAST6"
    }

    fn block_size(&self) -> usize {
        CAST6_BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherError::NotInitialised);
        }
        if input.len() < CAST6_BLOCK_BYTES || output.len() < CAST6_BLOCK_BYTES {
            return Err(BlockCipherError::BufferTooShort);
        }

        let input: &[u8; CAST6_BLOCK_BYTES] = input[..CAST6_BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; CAST6_BLOCK_BYTES] =
            (&mut output[..CAST6_BLOCK_BYTES]).try_into().unwrap();
        if self.for_encryption {
            self.schedule.encrypt_block(input, output);
        } else {
            self.schedule.decrypt_block(input, output);
        }
        Ok(CAST6_BLOCK_BYTES)
    }
}

impl BlockCipherInit for Cast6Engine {
    type Params<'a> = Cast6Params;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.schedule.set_key(params.key());
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_processing_errors() {
        let mut engine = Cast6Engine::new();
        assert_eq!(engine.algorithm_name(), "CAST6");
        assert_eq!(engine.block_size(), CAST6_BLOCK_BYTES);
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 16]),
            Err(BlockCipherError::NotInitialised)
        );

        engine
            .init(
                CipherDirection::Encrypt,
                &Cast6Params::new(&[0u8; 16]).unwrap(),
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
