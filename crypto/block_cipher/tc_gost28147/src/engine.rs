//! GOST 28147 block-cipher engine.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyWithSBoxParams;

use crate::cipher::{self, SUBKEYS};
use crate::s_box::BYTES as S_BOX_BYTES;
use crate::{BLOCK_BYTES, KEY_BYTES};

/// GOST 28147-89 with a 32-byte key, an S-box, and an 8-byte block.
pub struct Gost28147Engine {
    subkeys: [u32; SUBKEYS],
    s_box: [u8; S_BOX_BYTES],
    for_encryption: bool,
    initialised: bool,
}

impl Gost28147Engine {
    /// Creates an uninitialised GOST 28147 engine.
    pub const fn new() -> Self {
        Self {
            subkeys: [0; SUBKEYS],
            s_box: crate::s_box::DEFAULT,
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for Gost28147Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for Gost28147Engine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("Gost28147")
    }
}

impl BlockCipher for Gost28147Engine {
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

        let input: &[u8; BLOCK_BYTES] = input[..BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; BLOCK_BYTES] = (&mut output[..BLOCK_BYTES]).try_into().unwrap();
        cipher::process_block(
            &self.subkeys,
            &self.s_box,
            self.for_encryption,
            input,
            output,
        );
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyWithSBoxParams + ?Sized> BlockCipherInit<P> for Gost28147Engine {
    type Error = InitError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| InitError::InvalidKeyLength(key.len()))?;

        // 只檢查長度,不檢查內容 —— 與 bc 的 `Gost28147Engine.Init` 一致。
        let table = params.s_box();
        let table: &[u8; S_BOX_BYTES] = table
            .try_into()
            .map_err(|_| InitError::InvalidSBoxLength(table.len()))?;

        self.subkeys = cipher::expand_key(key);
        self.s_box = *table;
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}
