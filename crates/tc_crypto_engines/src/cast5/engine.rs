//! CAST5 block-cipher engine.

use tc_crypto_core::BlockCipher;

use super::{CAST5_BLOCK_BYTES, Cast5Error, Cast5Params, cipher};

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
    type Params<'a> = Cast5Params;
    type Error = Cast5Error;

    fn algorithm_name(&self) -> &str {
        "CAST5"
    }

    fn block_size(&self) -> usize {
        CAST5_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.schedule.set_key(params.key());
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(Cast5Error::NotInitialised);
        }
        if input.len() < CAST5_BLOCK_BYTES || output.len() < CAST5_BLOCK_BYTES {
            return Err(Cast5Error::BufferTooShort);
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
            Err(Cast5Error::NotInitialised)
        );

        engine
            .init(true, &Cast5Params::new(&[0u8; 5]).unwrap())
            .unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 7], &mut [0u8; 8]),
            Err(Cast5Error::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 7]),
            Err(Cast5Error::BufferTooShort)
        );
    }
}
