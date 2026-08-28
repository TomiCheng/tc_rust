//! CAST6 block-cipher engine.

use tc_crypto_core::BlockCipher;

use super::{CAST6_BLOCK_BYTES, Cast6Error, Cast6Params, cipher};

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
    type Params<'a> = Cast6Params;
    type Error = Cast6Error;

    fn algorithm_name(&self) -> &str {
        "CAST6"
    }

    fn block_size(&self) -> usize {
        CAST6_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.schedule.set_key(params.key());
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(Cast6Error::NotInitialised);
        }
        if input.len() < CAST6_BLOCK_BYTES || output.len() < CAST6_BLOCK_BYTES {
            return Err(Cast6Error::BufferTooShort);
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
            Err(Cast6Error::NotInitialised)
        );

        engine
            .init(true, &Cast6Params::new(&[0u8; 16]).unwrap())
            .unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 15], &mut [0u8; 16]),
            Err(Cast6Error::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 15]),
            Err(Cast6Error::BufferTooShort)
        );
    }
}
