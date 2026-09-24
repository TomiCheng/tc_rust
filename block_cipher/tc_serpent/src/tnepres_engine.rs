//! Tnepres block-cipher engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::cipher::{Representation, WORKING_KEY_WORDS};
use crate::{BLOCK_BYTES, KEY_STEP_BYTES, MAX_KEY_BYTES, MIN_KEY_BYTES, TNEPRES_ALGO_NAME, cipher};

/// Tnepres with a 4- to 32-byte key in four-byte steps and a 16-byte block.
/// Uses the byte- and word-reversed AES-submission representation, not a Serpent alias.
///
/// Constant time with respect to key and block contents: bitsliced S-boxes
/// use Boolean operations, without secret-dependent branches or table indices.
/// Key length, representation and direction are public.
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
/// use tc_serpent_v2::{BLOCK_BYTES, MAX_KEY_BYTES, TnepresEngine};
///
/// let key = [0x42; MAX_KEY_BYTES];
/// let plaintext = [0x11; BLOCK_BYTES];
/// let mut engine = TnepresEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct TnepresEngine {
    working_key: [u32; WORKING_KEY_WORDS],
    for_encryption: bool,
    initialised: bool,
}

impl TnepresEngine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    pub const fn new() -> Self {
        Self {
            working_key: [0; WORKING_KEY_WORDS],
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for TnepresEngine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TnepresEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(TNEPRES_ALGO_NAME)
    }
}

impl Drop for TnepresEngine {
    fn drop(&mut self) {
        self.working_key.zeroize();
    }
}

impl BlockCipher for TnepresEngine {
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
            cipher::encrypt_block(&self.working_key, Representation::Tnepres, input, output);
        } else {
            cipher::decrypt_block(&self.working_key, Representation::Tnepres, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for TnepresEngine {
    type Error = InitError;

    /// Installs a 4- to 32-byte key in four-byte steps for the selected direction, without borrowing it.
    ///
    /// An invalid length leaves the previous key, direction and initialization
    /// state unchanged. Constant time with respect to key contents; key
    /// length and direction are public.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !(MIN_KEY_BYTES..=MAX_KEY_BYTES)
            .step_by(KEY_STEP_BYTES)
            .any(|length| length == key.len())
        {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let for_encryption = direction == CipherDirection::Encrypt;
        self.working_key.zeroize();
        // Both directions use the same schedule, traversed in opposite orders.
        let mut expanded = cipher::expand_key(key, Representation::Tnepres);
        self.working_key.copy_from_slice(&expanded);
        expanded.zeroize();
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }
}
