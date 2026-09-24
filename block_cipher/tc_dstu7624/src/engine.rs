//! DSTU 7624 block-cipher engines.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::{ALGO_NAME, cipher};

/// Portable DSTU 7624 engine whose const parameter counts 64-bit block words.
///
/// Prefer the [`Dstu7624Engine128`], [`Dstu7624Engine256`], and [`Dstu7624Engine512`] aliases.
///
/// Variable time: key setup and block processing use secret-dependent S-box
/// lookups. Use only where cache-timing leakage is outside the threat model;
/// this crate provides no constant-time alternative.
///
/// Stored round keys are wiped on replacement and drop. This does not wipe
/// caller buffers or guarantee erasure of every register or stack copy.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_dstu7624_v2::Dstu7624Engine128;
///
/// let key = [0x42; 32];
/// let plaintext = [0x11; 16];
/// let mut engine = Dstu7624Engine128::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; 16];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; 16];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct Dstu7624Engine<const BLOCK_WORDS: usize> {
    cipher: cipher::Dstu7624Cipher<BLOCK_WORDS>,
    for_encryption: bool,
    initialised: bool,
}

/// DSTU 7624 with a 128-bit block and a 128- or 256-bit key.
pub type Dstu7624Engine128 = Dstu7624Engine<2>;
/// DSTU 7624 with a 256-bit block and a 256- or 512-bit key.
pub type Dstu7624Engine256 = Dstu7624Engine<4>;
/// DSTU 7624 with a 512-bit block and a 512-bit key.
pub type Dstu7624Engine512 = Dstu7624Engine<8>;

macro_rules! impl_engine {
    ($block_words:literal, [$($key_bytes:literal),+ $(,)?]) => {
        impl Dstu7624Engine<$block_words> {
            /// Creates an uninitialised engine. Constant time.
            pub const fn new() -> Self {
                Self {
                    cipher: cipher::Dstu7624Cipher::new(),
                    for_encryption: false,
                    initialised: false,
                }
            }
        }

        impl Default for Dstu7624Engine<$block_words> {
            /// Creates an uninitialised engine. Constant time.
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for Dstu7624Engine<$block_words> {
            /// Writes the algorithm name without inspecting key material.
            /// Constant time with respect to the key; output timing depends on the formatter.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(ALGO_NAME)
            }
        }

        impl BlockCipher for Dstu7624Engine<$block_words> {
            type Error = BlockError;

            /// Returns the selected block length in bytes. Constant time.
            fn block_size(&self) -> usize {
                $block_words * 8
            }

            /// Processes one block and returns its length, preserving any output tail.
            ///
            /// Returns `NotInitialised` or `BufferTooShort` without touching output.
            /// Variable time: secret-dependent S-box lookups can leak key information.
            fn process_block(
                &mut self,
                input: &[u8],
                output: &mut [u8],
            ) -> Result<usize, BlockError> {
                if !self.initialised {
                    return Err(BlockError::NotInitialised);
                }
                let block_bytes = self.block_size();
                if input.len() < block_bytes || output.len() < block_bytes {
                    return Err(BlockError::BufferTooShort);
                }

                if self.for_encryption {
                    self.cipher.encrypt_block(input, output);
                } else {
                    self.cipher.decrypt_block(input, output);
                }
                Ok(block_bytes)
            }
        }

        impl<P: KeyParams + ?Sized> BlockCipherInit<P> for Dstu7624Engine<$block_words> {
            type Error = InitError;

            /// Installs a key for the selected direction.
            ///
            /// Valid key lengths are 16 or 32 bytes for 128-bit blocks, 32 or
            /// 64 bytes for 256-bit blocks, and 64 bytes for 512-bit blocks.
            /// Invalid lengths preserve the previous key, direction and initialization state.
            /// Variable time: key setup uses secret-dependent S-box lookups.
            fn init(
                &mut self,
                direction: CipherDirection,
                params: &P,
            ) -> Result<(), InitError> {
                let key = params.key();
                if ![$($key_bytes),+].contains(&key.len()) {
                    return Err(InitError::InvalidKeyLength(key.len()));
                }

                self.cipher.set_key(key);
                self.for_encryption = direction == CipherDirection::Encrypt;
                self.initialised = true;
                Ok(())
            }
        }
    };
}

impl_engine!(2, [16, 32]);
impl_engine!(4, [32, 64]);
impl_engine!(8, [64]);

impl<const BLOCK_WORDS: usize> Drop for Dstu7624Engine<BLOCK_WORDS> {
    fn drop(&mut self) {
        self.cipher.zeroize();
    }
}
