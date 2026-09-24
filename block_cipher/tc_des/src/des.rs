//! DES block-cipher engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::cipher::{des_func, generate_working_key};
use crate::{BLOCK_BYTES, DES_ALGO_NAME, KEY_BYTES};

/// DES with an 8-byte encoded key and an 8-byte block.
///
/// For legacy interoperability only; do not use in new designs.
/// Parity bits are ignored and weak keys are not rejected.
///
/// Variable time: rounds index SP-boxes with secret data, and key setup
/// branches on key bits. Use only where cache-timing leakage is outside the
/// threat model; this crate provides no constant-time alternative.
///
/// Stored schedules are wiped on replacement and drop. This does not wipe
/// caller buffers or guarantee erasure of every register or stack copy.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_des_v2::{DesEngine, BLOCK_BYTES};
///
/// let key = [0x42; 8];
/// let plaintext = [0x11; BLOCK_BYTES];
/// let mut engine = DesEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct DesEngine {
    working_key: [u32; 32],
    initialised: bool,
}

impl DesEngine {
    /// Creates an uninitialised DES engine. Constant time.
    pub const fn new() -> Self {
        Self {
            working_key: [0; 32],
            initialised: false,
        }
    }
}

impl Default for DesEngine {
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DesEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(DES_ALGO_NAME)
    }
}

impl Drop for DesEngine {
    fn drop(&mut self) {
        self.working_key.zeroize();
    }
}

impl BlockCipher for DesEngine {
    type Error = BlockError;

    /// Returns the 8-byte block size. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Processes the first block and returns 8, preserving the output tail.
    ///
    /// Returns `NotInitialised` or `BufferTooShort` without touching output.
    /// Variable time: secret-dependent SP-box lookups can leak key information.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }
        if input.len() < BLOCK_BYTES || output.len() < BLOCK_BYTES {
            return Err(BlockError::BufferTooShort);
        }

        let mut high = u32::from_be_bytes(input[..4].try_into().unwrap());
        let mut low = u32::from_be_bytes(input[4..BLOCK_BYTES].try_into().unwrap());
        des_func(&self.working_key, &mut high, &mut low);
        output[..4].copy_from_slice(&high.to_be_bytes());
        output[4..BLOCK_BYTES].copy_from_slice(&low.to_be_bytes());
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for DesEngine {
    type Error = InitError;

    /// Installs an 8-byte encoded key for the selected direction.
    ///
    /// Invalid lengths preserve the previous key, direction and initialization state.
    /// Parity bits are ignored and weak keys are accepted.
    /// Variable time: key setup branches on secret key bits.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| InitError::InvalidKeyLength(key.len()))?;
        self.working_key.zeroize();
        let mut expanded = generate_working_key(direction == CipherDirection::Encrypt, key);
        self.working_key.copy_from_slice(&expanded);
        expanded.zeroize();
        self.initialised = true;
        Ok(())
    }
}
