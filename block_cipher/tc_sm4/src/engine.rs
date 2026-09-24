//! SM4 block-cipher engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::cipher::ROUNDS;
use crate::{ALGO_NAME, BLOCK_BYTES, KEY_BYTES, cipher};

/// SM4 with a 16-byte key and a 16-byte block.
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
/// use tc_sm4_v2::{BLOCK_BYTES, KEY_BYTES, Sm4Engine};
///
/// let key = [0x42; KEY_BYTES];
/// let plaintext = [0x11; BLOCK_BYTES];
/// let mut engine = Sm4Engine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Sm4Engine {
    round_keys: [u32; ROUNDS],
    initialised: bool,
}

impl Sm4Engine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    pub const fn new() -> Self {
        Self {
            round_keys: [0; ROUNDS],
            initialised: false,
        }
    }
}

impl Default for Sm4Engine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Sm4Engine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl Drop for Sm4Engine {
    fn drop(&mut self) {
        self.round_keys.zeroize();
    }
}

impl BlockCipher for Sm4Engine {
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
        cipher::process_block(&self.round_keys, input, output);
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for Sm4Engine {
    type Error = InitError;

    /// Installs a 16-byte key for the selected direction, without borrowing it.
    ///
    /// An invalid length leaves the previous key, direction and initialization
    /// state unchanged. Variable time: key expansion uses secret-dependent
    /// S-box lookups.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| InitError::InvalidKeyLength(key.len()))?;
        let for_encryption = direction == CipherDirection::Encrypt;
        self.round_keys.zeroize();
        cipher::expand_key(for_encryption, key, &mut self.round_keys);
        self.initialised = true;
        Ok(())
    }
}
