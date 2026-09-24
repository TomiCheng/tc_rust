//! RC5-32 block-cipher engine.

use core::fmt;

use tc_block_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_zeroize::Zeroize;

use crate::cipher::Core;
use crate::{MAX_KEY_BYTES, MAX_ROUNDS, RC5_32_ALGO_NAME, RC5_32_BLOCK_BYTES, Rc5Params};

/// RC5-32 with 1- to 255-byte keys, 0 to 255 rounds and a 8-byte block.
///
/// Constant time on mainstream x86, x86-64 and AArch64 processors with
/// operand-independent rotations. Processors without a barrel shifter can
/// leak through data-dependent rotation counts. Key length, rounds and direction
/// are public; this guarantee does not cover all processors.
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
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_rc5_v2::{Params, Rc532Engine, RC5_32_BLOCK_BYTES};
///
/// let key = [0x42; 16];
/// let params = Params::with_default_rounds(&key);
/// let plaintext = [0x11; RC5_32_BLOCK_BYTES];
/// let mut engine = Rc532Engine::new();
/// engine.init(CipherDirection::Encrypt, &params)?;
/// let mut encrypted = [0; RC5_32_BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; RC5_32_BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Rc532Engine {
    core: Core<u32>,
    for_encryption: bool,
    initialised: bool,
}

impl Rc532Engine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    pub const fn new() -> Self {
        Self {
            core: Core::new(),
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for Rc532Engine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Rc532Engine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(RC5_32_ALGO_NAME)
    }
}

impl Drop for Rc532Engine {
    fn drop(&mut self) {
        self.core.zeroize();
    }
}

impl BlockCipher for Rc532Engine {
    type Error = BlockError;

    /// Returns the 8-byte block size. Constant time.
    fn block_size(&self) -> usize {
        RC5_32_BLOCK_BYTES
    }

    /// Transforms the first block and returns 8, leaving any output tail untouched.
    ///
    /// Returns `NotInitialised` before successful initialization, or
    /// `BufferTooShort` when either buffer is shorter than 8 bytes.
    /// Both errors leave output untouched.
    /// Constant time on processors with operand-independent rotations.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }
        let (Some(input), Some(output)) = (
            input.first_chunk::<RC5_32_BLOCK_BYTES>(),
            output.first_chunk_mut::<RC5_32_BLOCK_BYTES>(),
        ) else {
            return Err(BlockError::BufferTooShort);
        };
        if self.for_encryption {
            self.core.encrypt(input, output);
        } else {
            self.core.decrypt(input, output);
        }
        Ok(RC5_32_BLOCK_BYTES)
    }
}

impl<P: Rc5Params + ?Sized> BlockCipherInit<P> for Rc532Engine {
    type Error = InitError;

    /// Installs a 1- to 255-byte key with 0 to 255 rounds for the selected direction.
    ///
    /// Invalid parameters preserve the previous key, direction and initialization state.
    /// Constant time on processors with operand-independent rotations; lengths and rounds are public.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let rounds = params.rounds();
        if rounds > MAX_ROUNDS {
            return Err(InitError::InvalidRounds(rounds));
        }
        self.core.expand_key(key, rounds);
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}
