//! CAST5 block-cipher engine.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::{BlockCipherError, CAST5_BLOCK_BYTES, Cast5Params, cipher};

/// Portable CAST5 (CAST-128) block cipher.
pub struct Cast5Engine {
    schedule: cipher::Cast5KeySchedule,
    for_encryption: bool,
    initialised: bool,
}

impl Cast5Engine {
    /// Creates an uninitialised CAST5 engine.
    pub const fn new() -> Self {
        Self {
            schedule: cipher::Cast5KeySchedule::new(),
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for Cast5Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for Cast5Engine {
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "CAST5"
    }

    fn block_size(&self) -> usize {
        CAST5_BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherError::NotInitialised);
        }
        if input.len() < CAST5_BLOCK_BYTES || output.len() < CAST5_BLOCK_BYTES {
            return Err(BlockCipherError::BufferTooShort);
        }

        let input: &[u8; CAST5_BLOCK_BYTES] = input[..CAST5_BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; CAST5_BLOCK_BYTES] =
            (&mut output[..CAST5_BLOCK_BYTES]).try_into().unwrap();
        if self.for_encryption {
            self.schedule.encrypt_block(input, output);
        } else {
            self.schedule.decrypt_block(input, output);
        }
        Ok(CAST5_BLOCK_BYTES)
    }
}

impl BlockCipherInit for Cast5Engine {
    type Params<'a> = Cast5Params;

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
        let mut engine = Cast5Engine::new();
        assert_eq!(engine.algorithm_name(), "CAST5");
        assert_eq!(engine.block_size(), CAST5_BLOCK_BYTES);
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 8]),
            Err(BlockCipherError::NotInitialised)
        );

        engine
            .init(
                CipherDirection::Encrypt,
                &Cast5Params::new(&[0u8; 5]).unwrap(),
            )
            .unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 7], &mut [0u8; 8]),
            Err(BlockCipherError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 7]),
            Err(BlockCipherError::BufferTooShort)
        );
    }
}
