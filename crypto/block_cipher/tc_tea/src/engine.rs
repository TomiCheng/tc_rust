//! TEA and XTEA block-cipher engines.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::cipher::{tea, xtea};
use crate::{BLOCK_BYTES, KEY_BYTES};

/// Narrows an initialization key to the fixed length both ciphers require.
fn checked_key<'a>(params: &'a (dyn KeyParams + 'a)) -> Result<&'a [u8; KEY_BYTES], InitError> {
    let key = params.key();
    key.try_into()
        .map_err(|_| InitError::InvalidKeyLength(key.len()))
}

/// Narrows the input and output buffers to exactly one block.
fn checked_block<'a>(
    initialised: bool,
    input: &'a [u8],
    output: &'a mut [u8],
) -> Result<(&'a [u8; BLOCK_BYTES], &'a mut [u8; BLOCK_BYTES]), BlockError> {
    if !initialised {
        return Err(BlockError::NotInitialised);
    }
    if input.len() < BLOCK_BYTES || output.len() < BLOCK_BYTES {
        return Err(BlockError::BufferTooShort);
    }
    Ok((
        input[..BLOCK_BYTES].try_into().unwrap(),
        (&mut output[..BLOCK_BYTES]).try_into().unwrap(),
    ))
}

/// TEA with a 16-byte key and an 8-byte block.
pub struct TeaEngine {
    key: [u32; 4],
    for_encryption: bool,
    initialised: bool,
}

impl TeaEngine {
    /// Creates an uninitialised TEA engine.
    pub const fn new() -> Self {
        Self {
            key: [0; 4],
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for TeaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for TeaEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("TEA")
    }
}

impl BlockCipher for TeaEngine {
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        let (input, output) = checked_block(self.initialised, input, output)?;
        if self.for_encryption {
            tea::encrypt_block(&self.key, input, output);
        } else {
            tea::decrypt_block(&self.key, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

impl BlockCipherInit for TeaEngine {
    type Params<'a> = dyn KeyParams + 'a;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        self.key = tea::expand_key(checked_key(params)?);
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}

/// XTEA with a 16-byte key and an 8-byte block.
///
/// XTEA is not a compatible variant of [`TeaEngine`]: the same key and block
/// bytes produce different ciphertext.
pub struct XteaEngine {
    schedule: xtea::Schedule,
    for_encryption: bool,
    initialised: bool,
}

impl XteaEngine {
    /// Creates an uninitialised XTEA engine.
    pub const fn new() -> Self {
        Self {
            schedule: [[0; 2]; crate::cipher::ROUNDS],
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for XteaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for XteaEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("XTEA")
    }
}

impl BlockCipher for XteaEngine {
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        let (input, output) = checked_block(self.initialised, input, output)?;
        if self.for_encryption {
            xtea::encrypt_block(&self.schedule, input, output);
        } else {
            xtea::decrypt_block(&self.schedule, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

impl BlockCipherInit for XteaEngine {
    type Params<'a> = dyn KeyParams + 'a;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        self.schedule = xtea::expand_key(checked_key(params)?);
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}
