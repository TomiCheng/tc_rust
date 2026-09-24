//! Camellia block-cipher engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::{ALGO_NAME, BLOCK_BYTES, KEY_BYTES, cipher};

/// Camellia using four 256-entry `u32` T-tables.
/// Camellia with a 16-, 24- or 32-byte key and a 16-byte block.
///
/// Variable time: key setup and block processing use secret-dependent
/// S-box lookups. Use only where cache-timing leakage is outside the
/// threat model; this crate provides no constant-time alternative.
///
/// The stored working key is wiped on replacement and drop. This does not
/// wipe caller buffers or guarantee erasure of every temporary copy in
/// registers or on the stack.
///
/// # Example
///
/// Import both traits and reinitialize the engine to change direction.
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_camellia_v2::{BLOCK_BYTES, KEY_BYTES, CamelliaEngine};
///
/// let key = [0x42; KEY_BYTES[0]];
/// let plaintext = [0x11; BLOCK_BYTES];
/// let mut engine = CamelliaEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct CamelliaEngine {
    schedule: cipher::CamelliaKeySchedule,
    initialised: bool,
}

impl CamelliaEngine {
    /// Creates an uninitialised Camellia engine. Constant time.
    pub const fn new() -> Self {
        Self {
            schedule: cipher::CamelliaKeySchedule::new(),
            initialised: false,
        }
    }
}

impl Default for CamelliaEngine {
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CamelliaEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl Drop for CamelliaEngine {
    fn drop(&mut self) {
        self.schedule.zeroize();
    }
}

impl BlockCipher for CamelliaEngine {
    type Error = BlockError;

    /// Returns the 16-byte block size. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Processes the first block and returns 16, preserving the output tail.
    ///
    /// Returns `NotInitialised` or `BufferTooShort` without touching output.
    /// Variable time: secret-dependent S-box lookups can leak key information.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }
        if input.len() < BLOCK_BYTES || output.len() < BLOCK_BYTES {
            return Err(BlockError::BufferTooShort);
        }

        let input: &[u8; BLOCK_BYTES] = input[..BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; BLOCK_BYTES] = (&mut output[..BLOCK_BYTES]).try_into().unwrap();
        self.schedule.process_block(input, output);
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for CamelliaEngine {
    type Error = InitError;

    /// Installs a 16-, 24- or 32-byte key for the selected direction.
    ///
    /// Invalid lengths preserve the previous key, direction and initialization state.
    /// Variable time: key setup uses secret-dependent S-box lookups.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !KEY_BYTES.contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        self.schedule
            .set_key(direction == CipherDirection::Encrypt, key);
        self.initialised = true;
        Ok(())
    }
}
