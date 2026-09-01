//! DES block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::cipher::{des_func, generate_working_key};
use crate::{BLOCK_BYTES, KEY_BYTES};

/// DES with an 8-byte encoded key and an 8-byte block.
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

impl AlgorithmName for DesEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("DES")
    }
}

impl BlockCipher for DesEngine {
    type Error = BlockError;

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
        des_func(&self.working_key, &mut high, &mut low);
        output[..4].copy_from_slice(&high.to_be_bytes());
        output[4..BLOCK_BYTES].copy_from_slice(&low.to_be_bytes());
        Ok(BLOCK_BYTES)
    }
}

impl BlockCipherInit for DesEngine {
    type Params<'a> = dyn KeyParams + 'a;
    type Error = InitError;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        let key = params.key();
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| InitError::InvalidKeyLength(key.len()))?;
        self.working_key = generate_working_key(direction == CipherDirection::Encrypt, key);
        self.initialised = true;
        Ok(())
    }
}
