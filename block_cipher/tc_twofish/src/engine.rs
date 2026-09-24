//! Twofish block-cipher engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::cipher::KeySchedule;
use crate::{ALGO_NAME, BLOCK_BYTES, KEY_BYTES, cipher};

/// Twofish with a 16-, 24- or 32-byte key and a 16-byte block.
///
/// Variable time: key setup and block processing use secret-dependent
/// table lookups; key setup also branches on key material. Use only where cache-timing leakage is outside the
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
/// use tc_twofish_v2::{BLOCK_BYTES, TwofishEngine};
///
/// let key = [0x42; 32];
/// let plaintext = [0x11; BLOCK_BYTES];
/// let mut engine = TwofishEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct TwofishEngine {
    schedule: KeySchedule,
    for_encryption: bool,
    initialised: bool,
}

impl TwofishEngine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    pub const fn new() -> Self {
        Self {
            schedule: KeySchedule::new(),
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for TwofishEngine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TwofishEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl Drop for TwofishEngine {
    fn drop(&mut self) {
        self.schedule.zeroize();
    }
}

impl BlockCipher for TwofishEngine {
    type Error = BlockError;

    /// Returns the 16-byte block size. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Transforms the first block and returns 16, leaving any output tail untouched.
    ///
    /// Returns `NotInitialised` before successful initialization, or
    /// `BufferTooShort` when either buffer is shorter than 16 bytes.
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

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for TwofishEngine {
    type Error = InitError;

    /// Installs a 16-, 24- or 32-byte key for the selected direction, without borrowing it.
    ///
    /// An invalid length leaves the previous key, direction and initialization
    /// state unchanged. Variable time: key expansion uses secret-dependent
    /// S-box lookups.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !KEY_BYTES.contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let for_encryption = direction == CipherDirection::Encrypt;
        self.schedule.zeroize();
        // Both directions use the same schedule, traversed in opposite orders.
        cipher::expand_key(key, &mut self.schedule);
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }
}
