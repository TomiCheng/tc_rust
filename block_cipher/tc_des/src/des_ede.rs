//! Triple DES block-cipher engine.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::cipher::{des_func, generate_working_key};
use crate::{BLOCK_BYTES, DES_EDE_ALGO_NAME, EDE2_KEY_BYTES, EDE3_KEY_BYTES};

/// EDE Triple DES with a 16-byte or 24-byte encoded key and an 8-byte block.
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
/// use tc_des_v2::{DesEdeEngine, BLOCK_BYTES};
///
/// let key = [0x42; 24];
/// let plaintext = [0x11; BLOCK_BYTES];
/// let mut engine = DesEdeEngine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; BLOCK_BYTES];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; BLOCK_BYTES];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct DesEdeEngine {
    working_key1: [u32; 32],
    working_key2: [u32; 32],
    working_key3: [u32; 32],
    for_encryption: bool,
    initialised: bool,
}

impl DesEdeEngine {
    /// Creates an uninitialised Triple DES engine. Constant time.
    pub const fn new() -> Self {
        Self {
            working_key1: [0; 32],
            working_key2: [0; 32],
            working_key3: [0; 32],
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for DesEdeEngine {
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DesEdeEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(DES_EDE_ALGO_NAME)
    }
}

impl Drop for DesEdeEngine {
    fn drop(&mut self) {
        self.working_key1.zeroize();
        self.working_key2.zeroize();
        self.working_key3.zeroize();
    }
}

impl BlockCipher for DesEdeEngine {
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
        if self.for_encryption {
            des_func(&self.working_key1, &mut high, &mut low);
            des_func(&self.working_key2, &mut high, &mut low);
            des_func(&self.working_key3, &mut high, &mut low);
        } else {
            des_func(&self.working_key3, &mut high, &mut low);
            des_func(&self.working_key2, &mut high, &mut low);
            des_func(&self.working_key1, &mut high, &mut low);
        }
        output[..4].copy_from_slice(&high.to_be_bytes());
        output[4..BLOCK_BYTES].copy_from_slice(&low.to_be_bytes());
        Ok(BLOCK_BYTES)
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for DesEdeEngine {
    type Error = InitError;

    /// Installs a 16- or 24-byte encoded key for the selected direction.
    ///
    /// Invalid lengths preserve the previous key, direction and initialization state.
    /// Parity bits are ignored and weak keys are accepted.
    /// Variable time: key setup branches on secret key bits.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let for_encryption = direction == CipherDirection::Encrypt;
        let key = params.key();
        if key.len() != EDE2_KEY_BYTES && key.len() != EDE3_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        let key1: &[u8; 8] = key[..8].try_into().unwrap();
        let key2: &[u8; 8] = key[8..16].try_into().unwrap();
        let key3: &[u8; 8] = if key.len() == EDE3_KEY_BYTES {
            key[16..24].try_into().unwrap()
        } else {
            key1
        };

        self.working_key1.zeroize();
        let mut expanded = generate_working_key(for_encryption, key1);
        self.working_key1.copy_from_slice(&expanded);
        expanded.zeroize();
        self.working_key2.zeroize();
        let mut expanded = generate_working_key(!for_encryption, key2);
        self.working_key2.copy_from_slice(&expanded);
        expanded.zeroize();
        self.working_key3.zeroize();
        let mut expanded = generate_working_key(for_encryption, key3);
        self.working_key3.copy_from_slice(&expanded);
        expanded.zeroize();
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }
}
