//! DES block-cipher engine.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::cipher;
use super::{BlockCipherError, DES_BLOCK_BYTES, DesParams};

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
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "DES"
    }

    fn block_size(&self) -> usize {
        DES_BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherError::NotInitialised);
        }
        if input.len() < DES_BLOCK_BYTES || output.len() < DES_BLOCK_BYTES {
            return Err(BlockCipherError::BufferTooShort);
        }

        let mut high = u32::from_be_bytes(input[..4].try_into().unwrap());
        let mut low = u32::from_be_bytes(input[4..8].try_into().unwrap());
        cipher::des_func(&self.working_key, &mut high, &mut low);
        output[..4].copy_from_slice(&high.to_be_bytes());
        output[4..8].copy_from_slice(&low.to_be_bytes());
        Ok(DES_BLOCK_BYTES)
    }
}

impl BlockCipherInit for DesEngine {
    type Params<'a> = DesParams;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.working_key =
            cipher::generate_working_key(direction == CipherDirection::Encrypt, params.key());
        self.initialised = true;
        Ok(())
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
            Err(BlockCipherError::NotInitialised)
        );

        let params = DesParams::new(&[0u8; 8]).unwrap();
        engine.init(CipherDirection::Encrypt, &params).unwrap();
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
