//! RC5-32 and RC5-64 block-cipher engines.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::Rc5Params;

use crate::cipher::Core;
use crate::{MAX_KEY_BYTES, MAX_ROUNDS, RC5_32_BLOCK_BYTES, RC5_64_BLOCK_BYTES};

macro_rules! define_engine {
    ($name:ident, $word:ty, $algo:literal, $block_bytes:ident) => {
        #[doc = concat!($algo, " block cipher.")]
        pub struct $name {
            core: Core<$word>,
            direction: CipherDirection,
            initialised: bool,
        }

        impl $name {
            #[doc = concat!("Creates an uninitialised ", $algo, " engine.")]
            pub fn new() -> Self {
                Self {
                    core: Core::new(),
                    direction: CipherDirection::Encrypt,
                    initialised: false,
                }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl AlgorithmName for $name {
            fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
                output.write_str($algo)
            }
        }

        impl BlockCipher for $name {
            type Error = BlockError;

            fn block_size(&self) -> usize {
                $block_bytes
            }

            fn process_block(
                &mut self,
                input: &[u8],
                output: &mut [u8],
            ) -> Result<usize, BlockError> {
                if !self.initialised {
                    return Err(BlockError::NotInitialised);
                }
                if input.len() < $block_bytes || output.len() < $block_bytes {
                    return Err(BlockError::BufferTooShort);
                }

                match self.direction {
                    CipherDirection::Encrypt => self.core.encrypt(input, output),
                    CipherDirection::Decrypt => self.core.decrypt(input, output),
                }
                Ok($block_bytes)
            }
        }

        impl<P: Rc5Params + ?Sized> BlockCipherInit<P> for $name {
            type Error = InitError;

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
                self.direction = direction;
                self.initialised = true;
                Ok(())
            }
        }
    };
}

define_engine!(Rc532Engine, u32, "RC5-32", RC5_32_BLOCK_BYTES);
define_engine!(Rc564Engine, u64, "RC5-64", RC5_64_BLOCK_BYTES);
