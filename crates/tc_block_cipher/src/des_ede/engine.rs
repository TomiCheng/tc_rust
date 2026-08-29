//! Triple DES block-cipher engine.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use crate::des::{des_func, generate_working_key};

use super::{BlockCipherError, DES_EDE_BLOCK_BYTES, DesEdeParams};

/// EDE Triple DES with a 16-byte or 24-byte encoded key and an 8-byte block.
pub struct DesEdeEngine {
    working_key1: [u32; 32],
    working_key2: [u32; 32],
    working_key3: [u32; 32],
    for_encryption: bool,
    initialised: bool,
}

impl DesEdeEngine {
    /// Creates an uninitialised Triple DES engine.
    pub const fn new() -> Self {
        Self {
            working_key1: [0; 32],
            working_key2: [0; 32],
            working_key3: [0; 32],
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for DesEdeEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for DesEdeEngine {
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "DESede"
    }

    fn block_size(&self) -> usize {
        DES_EDE_BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherError::NotInitialised);
        }
        if input.len() < DES_EDE_BLOCK_BYTES || output.len() < DES_EDE_BLOCK_BYTES {
            return Err(BlockCipherError::BufferTooShort);
        }

        let mut high = u32::from_be_bytes(input[..4].try_into().unwrap());
        let mut low = u32::from_be_bytes(input[4..8].try_into().unwrap());
        if self.for_encryption {
            des_func(&self.working_key1, &mut high, &mut low);
            des_func(&self.working_key2, &mut high, &mut low);
            des_func(&self.working_key3, &mut high, &mut low);
        } else {
            des_func(&self.working_key3, &mut high, &mut low);
            des_func(&self.working_key2, &mut high, &mut low);
            des_func(&self.working_key1, &mut high, &mut low);
        }
        output[..4].copy_from_slice(&high.to_be_bytes());
        output[4..8].copy_from_slice(&low.to_be_bytes());
        Ok(DES_EDE_BLOCK_BYTES)
    }
}

impl BlockCipherInit for DesEdeEngine {
    type Params<'a> = DesEdeParams;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        let for_encryption = direction == CipherDirection::Encrypt;
        let key = params.key();
        let key1: &[u8; 8] = key[..8].try_into().unwrap();
        let key2: &[u8; 8] = key[8..16].try_into().unwrap();
        let key3: &[u8; 8] = if key.len() == 24 {
            key[16..24].try_into().unwrap()
        } else {
            key1
        };

        self.working_key1 = generate_working_key(for_encryption, key1);
        self.working_key2 = generate_working_key(!for_encryption, key2);
        self.working_key3 = generate_working_key(for_encryption, key3);
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_processing_errors() {
        let mut engine = DesEdeEngine::new();
        assert_eq!(engine.algorithm_name(), "DESede");
        assert_eq!(engine.block_size(), DES_EDE_BLOCK_BYTES);
        assert_eq!(
            engine.process_block(&[0u8; 8], &mut [0u8; 8]),
            Err(BlockCipherError::NotInitialised)
        );

        let params = DesEdeParams::new(&[0u8; 16]).unwrap();
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
