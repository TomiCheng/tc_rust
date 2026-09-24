//! CAST6 block-cipher engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use super::{ALGO_NAME, BLOCK_BYTES, KEY_BYTES, cipher};

/// Portable CAST6 (CAST-256) block cipher.
///
/// Variable time: key setup and block processing use secret-dependent S-box
/// lookups. Use only where cache-timing leakage is outside the threat model;
/// this crate provides no constant-time alternative.
///
/// The stored schedules are wiped on replacement and drop. This does not wipe
/// caller buffers or guarantee erasure of every register or stack copy.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_cast_v2::{Cast6Engine, cast6::BLOCK_BYTES};
///
/// let mut engine = Cast6Engine::new();
/// let key = [0x42; 16];
/// let plaintext = [0x11; BLOCK_BYTES];
/// let mut ciphertext = [0; BLOCK_BYTES];
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// engine.process_block(&plaintext, &mut ciphertext)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&ciphertext, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Cast6Engine {
    schedule: cipher::Cast6KeySchedule,
    for_encryption: bool,
    initialised: bool,
}

impl Cast6Engine {
    /// Creates an uninitialised CAST6 engine. Constant time.
    pub const fn new() -> Self {
        Self {
            schedule: cipher::Cast6KeySchedule::new(),
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for Cast6Engine {
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Cast6Engine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl Drop for Cast6Engine {
    fn drop(&mut self) {
        self.schedule.zeroize();
    }
}

impl BlockCipher for Cast6Engine {
    type Error = BlockError;

    /// Returns the block length in bytes. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Processes one block and returns its length, preserving the output tail.
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
        if self.for_encryption {
            self.schedule.encrypt_block(input, output);
        } else {
            self.schedule.decrypt_block(input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for Cast6Engine {
    type Error = InitError;

    /// Installs a 16-, 20-, 24-, 28- or 32-byte key for the selected direction.
    ///
    /// Invalid lengths preserve the previous key, direction and initialization state.
    /// Variable time: key setup uses secret-dependent S-box lookups.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !KEY_BYTES.contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        self.schedule.set_key(key);
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}
