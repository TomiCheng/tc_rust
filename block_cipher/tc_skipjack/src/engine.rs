//! SKIPJACK block-cipher engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::cipher::{STEPS, Schedule};
use crate::{ALGO_NAME, BLOCK_BYTES, KEY_BYTES, cipher};

/// SKIPJACK with a 10-byte key and an 8-byte block.
///
/// Variable time: block processing uses secret-dependent F-table lookups. Use only where cache-timing leakage is outside the
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
/// use tc_skipjack_v2::{BLOCK_BYTES, KEY_BYTES, SkipjackEngine};
///
/// let key = [0x42; KEY_BYTES];
/// let plaintext = [0x11; BLOCK_BYTES];
/// let mut engine = SkipjackEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct SkipjackEngine {
    schedule: Schedule,
    for_encryption: bool,
    initialised: bool,
}

impl SkipjackEngine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    pub const fn new() -> Self {
        Self {
            schedule: [[0; 4]; STEPS],
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for SkipjackEngine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SkipjackEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl Drop for SkipjackEngine {
    fn drop(&mut self) {
        self.schedule.zeroize();
    }
}

impl BlockCipher for SkipjackEngine {
    type Error = BlockError;

    /// Returns the 8-byte block size. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Transforms the first block and returns 8, leaving any output tail untouched.
    ///
    /// Returns `NotInitialised` before successful initialization, or
    /// `BufferTooShort` when either buffer is shorter than 8 bytes.
    /// Both errors leave output untouched.
    /// Variable time: secret-dependent S-box lookups can leak key information.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }
        let (Some(input), Some(output)) = (
            input.first_chunk::<BLOCK_BYTES>(),
            output.first_chunk_mut::<BLOCK_BYTES>(),
        ) else {
            return Err(BlockError::BufferTooShort);
        };
        if self.for_encryption {
            cipher::encrypt_block(&self.schedule, input, output);
        } else {
            cipher::decrypt_block(&self.schedule, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for SkipjackEngine {
    type Error = InitError;

    /// Installs a 10-byte key for the selected direction, without borrowing it.
    ///
    /// An invalid length leaves the previous key, direction and initialization
    /// state unchanged. Constant time with respect to key contents: expansion
    /// only cycles through the key using public indices. A custom `KeyParams`
    /// implementation determines the timing of obtaining the key.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| InitError::InvalidKeyLength(key.len()))?;
        let for_encryption = direction == CipherDirection::Encrypt;
        self.schedule.zeroize();
        // Both directions use the same schedule, traversed in opposite orders.
        cipher::expand_key(key, &mut self.schedule);
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }
}
