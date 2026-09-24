//! ARIA block-cipher engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::cipher::{MAX_ROUND_KEYS, RoundKeys};
use crate::{ALGO_NAME, BLOCK_BYTES, KEY_BYTES, cipher};

/// Portable ARIA-128, ARIA-192, and ARIA-256 block cipher.
///
/// **Variable time:** key setup and block processing use secret-dependent S-box
/// lookups. Use only where cache-timing leakage is outside the threat model;
/// this crate does not currently provide a constant-time backend.
///
/// Stored round keys are wiped on drop. This does not wipe the caller's key
/// buffer or every temporary copy left in registers or on the stack.
///
/// # Example
///
/// Import the initialization and processing traits to use the engine.
/// Changing direction requires another call to `init`.
///
/// ```
/// use tc_aria::{AriaTableEngine, BLOCK_BYTES};
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
///
/// let mut engine = AriaTableEngine::new();
/// let key = [0x42; 32];
/// let plaintext = [0x11; BLOCK_BYTES];
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// assert_eq!(engine.to_string(), "ARIA");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct AriaTableEngine {
    round_keys: RoundKeys,
    rounds: usize,
    initialised: bool,
}

impl AriaTableEngine {
    /// Creates an uninitialised ARIA engine.
    /// Constant time: no key material is inspected.
    pub const fn new() -> Self {
        Self {
            round_keys: [[0; BLOCK_BYTES]; MAX_ROUND_KEYS],
            rounds: 0,
            initialised: false,
        }
    }
}

impl Default for AriaTableEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AriaTableEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl Drop for AriaTableEngine {
    fn drop(&mut self) {
        self.round_keys.zeroize();
    }
}

impl BlockCipher for AriaTableEngine {
    type Error = BlockError;

    /// Returns 16 bytes, regardless of key size. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Transforms the first 16 input bytes, leaving any output tail untouched.
    ///
    /// Returns `NotInitialised` before successful initialization, or
    /// `BufferTooShort` if either buffer holds less than a block. These errors
    /// leave the output untouched.
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
        cipher::process_block(&self.round_keys, self.rounds, input, output);
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for AriaTableEngine {
    type Error = InitError;

    /// Installs a 16-, 24- or 32-byte key for the selected direction.
    ///
    /// Invalid lengths preserve the previous key and direction. The engine
    /// keeps its own expanded key rather than borrowing the supplied bytes.
    /// Variable time: key expansion uses secret-dependent S-box lookups.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !KEY_BYTES.contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        let for_encryption = direction == CipherDirection::Encrypt;
        (self.round_keys, self.rounds) = cipher::key_schedule(for_encryption, key);
        self.initialised = true;
        Ok(())
    }
}
