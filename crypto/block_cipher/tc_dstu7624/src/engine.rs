//! DSTU 7624 block-cipher engines.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::cipher;

/// Portable DSTU 7624 engine whose const parameter counts 64-bit block words.
///
/// Prefer the [`Engine128`], [`Engine256`], and [`Engine512`] aliases.
pub struct Engine<const BLOCK_WORDS: usize> {
    cipher: cipher::Dstu7624Cipher<BLOCK_WORDS>,
    for_encryption: bool,
    initialised: bool,
}

/// DSTU 7624 with a 128-bit block and a 128- or 256-bit key.
pub type Engine128 = Engine<2>;
/// DSTU 7624 with a 256-bit block and a 256- or 512-bit key.
pub type Engine256 = Engine<4>;
/// DSTU 7624 with a 512-bit block and a 512-bit key.
pub type Engine512 = Engine<8>;

macro_rules! impl_engine {
    ($block_words:literal, [$($key_bytes:literal),+ $(,)?]) => {
        impl Engine<$block_words> {
            /// Creates an uninitialised engine.
            pub const fn new() -> Self {
                Self {
                    cipher: cipher::Dstu7624Cipher::new(),
                    for_encryption: false,
                    initialised: false,
                }
            }
        }

        impl Default for Engine<$block_words> {
            fn default() -> Self {
                Self::new()
            }
        }

        impl AlgorithmName for Engine<$block_words> {
            fn write_algo_name(
                &self,
                output: &mut dyn core::fmt::Write,
            ) -> core::fmt::Result {
                output.write_str("DSTU7624")
            }
        }

        impl BlockCipher for Engine<$block_words> {
            type Error = BlockError;

            fn block_size(&self) -> usize {
                $block_words * 8
            }

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

        impl<P: KeyParams + ?Sized> BlockCipherInit<P> for Engine<$block_words> {
            type Error = InitError;

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
