//! GOST 28147 block-cipher engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::cipher::{self, SUBKEYS};
use crate::s_box::BYTES as S_BOX_BYTES;
use crate::{ALGO_NAME, BLOCK_BYTES, KEY_BYTES, SBoxParams};

/// GOST 28147-89 with a 32-byte key, an S-box, and an 8-byte block.
///
/// Variable time: round functions index the supplied S-box with secret nibbles.
/// Use only where cache-timing leakage is outside the threat model; this crate
/// provides no constant-time alternative.
///
/// Stored subkeys and the S-box are wiped on replacement and drop. The S-box
/// may itself be secret in some profiles. This does not wipe caller buffers
/// or guarantee erasure of every register or stack copy.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
/// use tc_gost28147_v2::{Gost28147Engine, KeyWithSBox, s_box};
///
/// let key = [0x42; 32];
/// let params = KeyWithSBox::with_s_box(&key, &s_box::E_A);
/// let plaintext = [0x11; 8];
/// let mut engine = Gost28147Engine::new();
/// engine.init(CipherDirection::Encrypt, &params)?;
/// let mut encrypted = [0; 8];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &params)?;
/// let mut recovered = [0; 8];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Gost28147Engine {
    subkeys: [u32; SUBKEYS],
    s_box: [u8; S_BOX_BYTES],
    for_encryption: bool,
    initialised: bool,
}

impl Gost28147Engine {
    /// Creates an uninitialised GOST 28147 engine. Constant time.
    pub const fn new() -> Self {
        Self {
            subkeys: [0; SUBKEYS],
            s_box: crate::s_box::DEFAULT,
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for Gost28147Engine {
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Gost28147Engine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl Drop for Gost28147Engine {
    fn drop(&mut self) {
        self.subkeys.zeroize();
        self.s_box.zeroize();
    }
}

impl BlockCipher for Gost28147Engine {
    type Error = BlockError;

    /// Returns the 8-byte block size. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Processes one block and returns 8, preserving any output tail.
    ///
    /// Returns `NotInitialised` or `BufferTooShort` without touching output.
    /// Variable time: secret nibbles index the stored S-box.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }
        if input.len() < BLOCK_BYTES || output.len() < BLOCK_BYTES {
            return Err(BlockError::BufferTooShort);
        }

        let input: &[u8; BLOCK_BYTES] = input[..BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; BLOCK_BYTES] = (&mut output[..BLOCK_BYTES]).try_into().unwrap();
        cipher::process_block(
            &self.subkeys,
            &self.s_box,
            self.for_encryption,
            input,
            output,
        );
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + SBoxParams + ?Sized> BlockCipherInit<P> for Gost28147Engine {
    type Error = InitError;

    /// Installs a 32-byte key and a 128-byte S-box for the selected direction.
    ///
    /// Only lengths are checked; S-box contents are accepted unchanged.
    /// Invalid parameters preserve the previous key, S-box, direction and initialization state.
    /// Constant time with respect to key and S-box contents; lengths are public.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| InitError::InvalidKeyLength(key.len()))?;

        // Check only the length, matching Bouncy Castle's Gost28147Engine.Init.
        let table = params.s_box();
        let table: &[u8; S_BOX_BYTES] = table
            .try_into()
            .map_err(|_| InitError::InvalidSBoxLength(table.len()))?;

        self.subkeys.zeroize();
        self.s_box.zeroize();
        let mut expanded = cipher::expand_key(key);
        self.subkeys.copy_from_slice(&expanded);
        expanded.zeroize();
        self.s_box.copy_from_slice(table);
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}
