//! ARIA through the RustCrypto `aria` crate.

use aria::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aria::{Aria128, Aria192, Aria256};

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};

use crate::BLOCK_BYTES;

type Block = aria::cipher::Block<Aria128>;

enum Cipher {
    Aria128(Aria128),
    Aria192(Aria192),
    Aria256(Aria256),
}

/// ARIA backed by RustCrypto's `aria` crate, enabled with `rustcrypto`.
///
/// **Variable time:** the backend uses secret-dependent table lookups during
/// key setup and block processing. It is not a constant-time alternative to
/// `AriaTableEngine`. Stored keys are wiped on drop through the enabled
/// `zeroize` support; caller buffers and other copies remain the caller's.
///
/// # Example
///
/// Requires the `rustcrypto` Cargo feature; bypasses the automatic dispatcher.
///
/// ```
/// use tc_aria::AriaRustCryptoEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
///
/// let mut engine = AriaRustCryptoEngine::new();
/// let key = [0x42; 32];
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut output = [0; 16];
/// assert_eq!(engine.process_block(&[0; 16], &mut output)?, 16);
/// assert_eq!(engine.to_string(), "ARIA");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct AriaRustCryptoEngine {
    cipher: Option<Cipher>,
    direction: CipherDirection,
}

impl core::fmt::Display for AriaRustCryptoEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(crate::ALGO_NAME)
    }
}

impl AriaRustCryptoEngine {
    /// An engine without a key; `init` must come before `process_block`.
    /// Constant time.
    pub const fn new() -> Self {
        Self {
            cipher: None,
            direction: CipherDirection::Encrypt,
        }
    }
}

impl Default for AriaRustCryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for AriaRustCryptoEngine {
    type Error = InitError;

    /// Expands a 16-, 24- or 32-byte key. Invalid lengths preserve prior state.
    /// Variable time: the backend uses secret-dependent table lookups.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let invalid = |_| InitError::InvalidKeyLength(key.len());
        let cipher = match key.len() {
            16 => Cipher::Aria128(Aria128::new_from_slice(key).map_err(invalid)?),
            24 => Cipher::Aria192(Aria192::new_from_slice(key).map_err(invalid)?),
            32 => Cipher::Aria256(Aria256::new_from_slice(key).map_err(invalid)?),
            len => return Err(InitError::InvalidKeyLength(len)),
        };
        self.cipher = Some(cipher);
        self.direction = direction;
        Ok(())
    }
}

impl BlockCipher for AriaRustCryptoEngine {
    type Error = BlockError;

    /// Always 16. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Transforms the first input block, leaving the output tail unchanged.
    /// Returns `NotInitialised` or `BufferTooShort` without modifying output.
    /// Variable time: the backend uses secret-dependent table lookups.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        let cipher = self.cipher.as_ref().ok_or(BlockError::NotInitialised)?;
        let (Some(input), Some(output)) = (
            input.get(..BLOCK_BYTES).and_then(Block::slice_as_array),
            output
                .get_mut(..BLOCK_BYTES)
                .and_then(Block::slice_as_mut_array),
        ) else {
            return Err(BlockError::BufferTooShort);
        };
        match (cipher, self.direction) {
            (Cipher::Aria128(c), CipherDirection::Encrypt) => c.encrypt_block_b2b(input, output),
            (Cipher::Aria128(c), CipherDirection::Decrypt) => c.decrypt_block_b2b(input, output),
            (Cipher::Aria192(c), CipherDirection::Encrypt) => c.encrypt_block_b2b(input, output),
            (Cipher::Aria192(c), CipherDirection::Decrypt) => c.decrypt_block_b2b(input, output),
            (Cipher::Aria256(c), CipherDirection::Encrypt) => c.encrypt_block_b2b(input, output),
            (Cipher::Aria256(c), CipherDirection::Decrypt) => c.decrypt_block_b2b(input, output),
        }
        Ok(BLOCK_BYTES)
    }
}
