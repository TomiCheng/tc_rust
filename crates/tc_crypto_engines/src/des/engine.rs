//! DES block-cipher engine.

use tc_crypto_core::BlockCipher;

use super::cipher;
use super::{DES_BLOCK_BYTES, DesError, DesParams};

/// DES with an 8-byte encoded key and 8-byte block.
pub struct DesEngine {
    working_key: [u32; 32],
    initialised: bool,
}

impl DesEngine {
    /// Creates an uninitialised DES engine.
    pub const fn new() -> Self {
        Self {
            working_key: [0; 32],
            initialised: false,
        }
    }
}

impl Default for DesEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for DesEngine {
    type Params<'a> = DesParams;
    type Error = DesError;

    fn algorithm_name(&self) -> &str {
        "DES"
    }

    fn block_size(&self) -> usize {
        DES_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.working_key = cipher::generate_working_key(for_encryption, params.key());
        self.initialised = true;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(DesError::NotInitialised);
        }
        if input.len() < DES_BLOCK_BYTES || output.len() < DES_BLOCK_BYTES {
            return Err(DesError::BufferTooShort);
        }

        let mut high = u32::from_be_bytes(input[..4].try_into().unwrap());
        let mut low = u32::from_be_bytes(input[4..8].try_into().unwrap());
        cipher::des_func(&self.working_key, &mut high, &mut low);
        output[..4].copy_from_slice(&high.to_be_bytes());
        output[4..8].copy_from_slice(&low.to_be_bytes());
        Ok(DES_BLOCK_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_processing_errors() {
        let mut engine = DesEngine::new();
        assert_eq!(engine.algorithm_name(), "DES");
        assert_eq!(engine.block_size(), DES_BLOCK_BYTES);
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 8]),
            Err(DesError::NotInitialised)
        );

        let params = DesParams::new(&[0u8; 8]).unwrap();
        engine.init(true, &params).unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 7], &mut [0u8; 8]),
            Err(DesError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 7]),
            Err(DesError::BufferTooShort)
        );
    }
}
