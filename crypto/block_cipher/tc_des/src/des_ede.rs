//! Triple DES block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::cipher::{des_func, generate_working_key};
use crate::{BLOCK_BYTES, EDE2_KEY_BYTES, EDE3_KEY_BYTES};

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

impl AlgorithmName for DesEdeEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("DESede")
    }
}

impl BlockCipher for DesEdeEngine {
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }
        if input.len() < BLOCK_BYTES || output.len() < BLOCK_BYTES {
            return Err(BlockError::BufferTooShort);
        }

        let mut high = u32::from_be_bytes(input[..4].try_into().unwrap());
        let mut low = u32::from_be_bytes(input[4..BLOCK_BYTES].try_into().unwrap());
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
        output[4..BLOCK_BYTES].copy_from_slice(&low.to_be_bytes());
        Ok(BLOCK_BYTES)
    }
}

impl BlockCipherInit for DesEdeEngine {
    type Params<'a> = dyn KeyParams + 'a;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        let for_encryption = direction == CipherDirection::Encrypt;
        let key = params.key();
        if key.len() != EDE2_KEY_BYTES && key.len() != EDE3_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        let key1: &[u8; 8] = key[..8].try_into().unwrap();
        let key2: &[u8; 8] = key[8..16].try_into().unwrap();
        let key3: &[u8; 8] = if key.len() == EDE3_KEY_BYTES {
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
