//! IDEA block-cipher engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::cipher::SUBKEY_WORDS;
use crate::{ALGO_NAME, BLOCK_BYTES, KEY_BYTES, cipher};

/// IDEA with a 16-byte key and an 8-byte block.
///
/// Variable time: block processing branches on secret multiplication operands;
/// decryption key setup uses a key-dependent Euclidean loop and division.
/// Use only where timing leakage, including cache-timing leakage, is outside
/// the threat model; this crate provides no constant-time alternative.
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
/// use tc_idea_v2::{BLOCK_BYTES, KEY_BYTES, IdeaEngine};
///
/// let key = [0x42; KEY_BYTES];
/// let plaintext = [0x11; BLOCK_BYTES];
/// let mut engine = IdeaEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct IdeaEngine {
    working_key: [u16; SUBKEY_WORDS],
    initialised: bool,
}

impl IdeaEngine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    pub const fn new() -> Self {
        Self {
            working_key: [0; SUBKEY_WORDS],
            initialised: false,
        }
    }
}

impl Default for IdeaEngine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for IdeaEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl Drop for IdeaEngine {
    fn drop(&mut self) {
        self.working_key.zeroize();
    }
}

impl BlockCipher for IdeaEngine {
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
    /// Variable time: modular multiplication branches on secret values.
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
        cipher::process_block(&self.working_key, input, output);
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for IdeaEngine {
    type Error = InitError;

    /// Installs a 16-byte key for the selected direction, without borrowing it.
    ///
    /// An invalid length leaves the previous key, direction and initialization
    /// state unchanged. Variable time: decryption key expansion uses
    /// key-dependent Euclidean inverses.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| InitError::InvalidKeyLength(key.len()))?;
        let for_encryption = direction == CipherDirection::Encrypt;
        self.working_key.zeroize();
        cipher::generate_working_key(for_encryption, key, &mut self.working_key);
        self.initialised = true;
        Ok(())
    }
}
