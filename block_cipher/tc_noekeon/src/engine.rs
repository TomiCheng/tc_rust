//! Noekeon block-cipher engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::{ALGO_NAME, BLOCK_BYTES, KEY_BYTES, cipher};

/// Noekeon in direct-key mode, with a 16-byte key and a 16-byte block.
///
/// Constant time with respect to key and block contents: only bitwise
/// operations and fixed rotations are used. Branches depend on public
/// direction, initialization state and buffer lengths, not secret data.
///
/// The stored working key is wiped on replacement and drop. Caller buffers
/// and every temporary copy in registers or on the stack are not wiped.
///
/// # Example
///
/// Import both traits and reinitialize the engine to change direction.
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_noekeon_v2::{BLOCK_BYTES, KEY_BYTES, NoekeonEngine};
///
/// let key = [0x42; KEY_BYTES];
/// let plaintext = [0x11; BLOCK_BYTES];
/// let mut engine = NoekeonEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct NoekeonEngine {
    working_key: [u32; 4],
    for_encryption: bool,
    initialised: bool,
}

impl NoekeonEngine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    pub const fn new() -> Self {
        Self {
            working_key: [0; 4],
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for NoekeonEngine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for NoekeonEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl Drop for NoekeonEngine {
    fn drop(&mut self) {
        self.working_key.zeroize();
    }
}

impl BlockCipher for NoekeonEngine {
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
    /// Constant time with respect to key and block contents.
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
            cipher::encrypt_block(&self.working_key, input, output);
        } else {
            cipher::decrypt_block(&self.working_key, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for NoekeonEngine {
    type Error = InitError;

    /// Installs a 16-byte key for the selected direction, without borrowing it.
    ///
    /// An invalid length leaves the previous key, direction and initialization
    /// state unchanged. Constant time with respect to key contents; key length
    /// and direction are public. Obtaining the key through a custom
    /// `KeyParams` implementation has that implementation's timing behaviour.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| InitError::InvalidKeyLength(key.len()))?;
        let for_encryption = direction == CipherDirection::Encrypt;
        self.working_key.zeroize();
        cipher::prepare_key(for_encryption, key, &mut self.working_key);
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }
}
