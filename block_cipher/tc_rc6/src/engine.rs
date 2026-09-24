//! RC6 block-cipher engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::cipher::SUBKEYS;
use crate::{ALGO_NAME, BLOCK_BYTES, MAX_KEY_BYTES, cipher};

/// RC6-32/20 with a 1- to 255-byte key and a 16-byte block.
///
/// Constant time with respect to key and block contents on mainstream x86,
/// x86-64 and AArch64 processors with fixed-latency data-dependent rotations
/// and 32-bit multiplication. Processors without a barrel shifter or with
/// early-terminating multipliers can leak secret data. Key length and
/// direction are public. This crate does not provide a hardware-independent
/// timing guarantee.
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
/// use tc_rc6_v2::{BLOCK_BYTES, Rc6Engine};
///
/// let key = [0x42; 16];
/// let plaintext = [0x11; BLOCK_BYTES];
/// let mut engine = Rc6Engine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Rc6Engine {
    subkeys: [u32; SUBKEYS],
    for_encryption: bool,
    initialised: bool,
}

impl Rc6Engine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    pub const fn new() -> Self {
        Self {
            subkeys: [0; SUBKEYS],
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for Rc6Engine {
    /// Creates an uninitialised engine. Constant time: no key is inspected.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Rc6Engine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl Drop for Rc6Engine {
    fn drop(&mut self) {
        self.subkeys.zeroize();
    }
}

impl BlockCipher for Rc6Engine {
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
    /// Constant time under the hardware requirements documented on the engine.
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
            cipher::encrypt(&self.subkeys, input, output);
        } else {
            cipher::decrypt(&self.subkeys, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for Rc6Engine {
    type Error = InitError;

    /// Installs a 1- to 255-byte key for the selected direction, without borrowing it.
    ///
    /// An invalid length leaves the previous key, direction and initialization
    /// state unchanged. Constant time with respect to key contents under
    /// the engine's hardware requirements. Key length and direction are public.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let for_encryption = direction == CipherDirection::Encrypt;
        self.subkeys.zeroize();
        // Both directions use the same schedule, traversed in opposite orders.
        cipher::expand_key(key, &mut self.subkeys);
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }
}
