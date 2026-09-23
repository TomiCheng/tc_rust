//! AES through the RustCrypto `aes` crate.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256, Block};
use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};

use crate::BLOCK_BYTES;

enum Cipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

/// AES backed by the RustCrypto `aes` crate, which picks AES-NI, VAES or
/// ARMv8 at runtime and otherwise a bitsliced software implementation with
/// no table lookups. Constant time on every backend; its round keys are wiped
/// on drop.
///
/// # Example
///
/// Requires the `rustcrypto` Cargo feature; bypasses the automatic dispatcher.
///
/// ```
/// use tc_aes::AesRustCryptoEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
///
/// let mut engine = AesRustCryptoEngine::new();
/// let key = [0x42; 32];
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut output = [0; 16];
/// assert_eq!(engine.process_block(&[0; 16], &mut output)?, 16);
/// assert_eq!(engine.to_string(), "AES");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct AesRustCryptoEngine {
    cipher: Option<Cipher>,
    direction: CipherDirection,
}

impl core::fmt::Display for AesRustCryptoEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(crate::ALGO_NAME)
    }
}

impl AesRustCryptoEngine {
    /// An engine without a key; `init` must come before `process_block`.
    /// Constant time.
    pub const fn new() -> Self {
        Self {
            cipher: None,
            direction: CipherDirection::Encrypt,
        }
    }
}

impl Default for AesRustCryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for AesRustCryptoEngine {
    type Error = InitError;

    /// Expands a 16-, 24- or 32-byte key. Branches on the key length, which is
    /// public, and is otherwise constant time. A rejected key leaves the
    /// previous state in place.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let invalid = |_| InitError::InvalidKeyLength(key.len());
        let cipher = match key.len() {
            16 => Cipher::Aes128(Aes128::new_from_slice(key).map_err(invalid)?),
            24 => Cipher::Aes192(Aes192::new_from_slice(key).map_err(invalid)?),
            32 => Cipher::Aes256(Aes256::new_from_slice(key).map_err(invalid)?),
            len => return Err(InitError::InvalidKeyLength(len)),
        };
        self.cipher = Some(cipher);
        self.direction = direction;
        Ok(())
    }
}

impl BlockCipher for AesRustCryptoEngine {
    type Error = BlockError;

    /// Always 16. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Transforms the first 16 bytes of `input` into the first 16 of
    /// `output`. Constant time in the key and the data; branches only on
    /// the key size and direction.
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
            (Cipher::Aes128(c), CipherDirection::Encrypt) => c.encrypt_block_b2b(input, output),
            (Cipher::Aes128(c), CipherDirection::Decrypt) => c.decrypt_block_b2b(input, output),
            (Cipher::Aes192(c), CipherDirection::Encrypt) => c.encrypt_block_b2b(input, output),
            (Cipher::Aes192(c), CipherDirection::Decrypt) => c.decrypt_block_b2b(input, output),
            (Cipher::Aes256(c), CipherDirection::Encrypt) => c.encrypt_block_b2b(input, output),
            (Cipher::Aes256(c), CipherDirection::Decrypt) => c.decrypt_block_b2b(input, output),
        }
        Ok(BLOCK_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::AesRustCryptoEngine;
    use crate::common::test_support as support;

    #[test]
    fn fips_197_vectors_encrypt_and_decrypt_under_every_key_size() {
        support::check_fips_197(AesRustCryptoEngine::new);
    }

    #[test]
    fn processing_before_init_is_rejected() {
        support::check_uninitialised(AesRustCryptoEngine::new);
    }

    #[test]
    fn short_buffers_are_rejected_and_longer_ones_get_exactly_one_block() {
        support::check_buffers(AesRustCryptoEngine::new);
    }

    #[test]
    fn a_rejected_key_length_keeps_the_previous_key() {
        support::check_rejected_key(AesRustCryptoEngine::new);
    }
}
