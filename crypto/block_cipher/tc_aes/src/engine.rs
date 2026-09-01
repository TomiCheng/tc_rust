//! AES engine with runtime backend dispatch.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::BLOCK_BYTES;
use crate::cipher::{self, RoundKeys};

#[derive(Clone, Copy)]
enum Backend {
    Portable,
    #[cfg(aes_ni)]
    AesNi(crate::x86::AesNi),
}

fn detect_backend() -> Backend {
    #[cfg(aes_ni)]
    if let Some(token) = crate::x86::AesNi::detect() {
        return Backend::AesNi(token);
    }
    Backend::Portable
}

/// AES with a 16-byte block and a 16-, 24-, or 32-byte key.
///
/// On x86 and x86_64 this detects AES-NI when the engine is constructed and
/// uses it when present, falling back to the portable T-table backend
/// otherwise. Build with the `force-portable-aes` feature to compile the
/// accelerated path out entirely; construct [`AesLightEngine`] instead when the
/// small-footprint implementation is wanted even where AES-NI is available.
///
/// [`AesLightEngine`]: crate::AesLightEngine
pub struct AesEngine {
    round_keys: RoundKeys,
    rounds: usize,
    for_encryption: bool,
    initialised: bool,
    backend: Backend,
}

impl AesEngine {
    /// Creates an uninitialised AES engine, selecting the best backend.
    pub fn new() -> Self {
        Self {
            round_keys: [[0; BLOCK_BYTES]; cipher::MAX_ROUND_KEYS],
            rounds: 0,
            for_encryption: false,
            initialised: false,
            backend: detect_backend(),
        }
    }

    fn transform(&self, input: &[u8; BLOCK_BYTES], output: &mut [u8; BLOCK_BYTES]) {
        match (self.backend, self.for_encryption) {
            (Backend::Portable, true) => {
                cipher::encrypt_block(&self.round_keys, self.rounds, input, output);
            }
            (Backend::Portable, false) => {
                cipher::decrypt_block(&self.round_keys, self.rounds, input, output);
            }
            #[cfg(aes_ni)]
            (Backend::AesNi(token), true) => {
                token.encrypt_block(&self.round_keys, self.rounds, input, output);
            }
            #[cfg(aes_ni)]
            (Backend::AesNi(token), false) => {
                token.decrypt_block(&self.round_keys, self.rounds, input, output);
            }
        }
    }
}

impl Default for AesEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for AesEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("AES")
    }
}

impl BlockCipher for AesEngine {
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }
        if input.len() < BLOCK_BYTES || output.len() < BLOCK_BYTES {
            return Err(BlockError::BufferTooShort);
        }

        let input: &[u8; BLOCK_BYTES] = input[..BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; BLOCK_BYTES] = (&mut output[..BLOCK_BYTES]).try_into().unwrap();
        self.transform(input, output);
        Ok(BLOCK_BYTES)
    }
}

impl BlockCipherInit for AesEngine {
    type Params<'a> = dyn KeyParams + 'a;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        let key = params.key();
        let rounds = cipher::rounds_for(key.len()).ok_or(InitError::InvalidKeyLength(key.len()))?;

        let for_encryption = direction == CipherDirection::Encrypt;
        self.round_keys = cipher::expand_key(key, rounds);
        self.rounds = rounds;
        self.for_encryption = for_encryption;

        // 解密輪金鑰的換算方式與後端相依:AES-NI 用 AESIMC 指令,可攜版自己算。
        if !for_encryption {
            match self.backend {
                Backend::Portable => {
                    cipher::prepare_decryption_keys(&mut self.round_keys, rounds);
                }
                #[cfg(aes_ni)]
                Backend::AesNi(token) => {
                    token.prepare_decryption_keys(&mut self.round_keys, rounds);
                }
            }
        }

        self.initialised = true;
        Ok(())
    }
}

#[cfg(all(test, aes_ni))]
mod tests {
    use super::*;

    /// Which backend runs is decided at runtime, so the accelerated one has to
    /// agree with the portable one on every input.
    #[test]
    fn aes_ni_matches_the_portable_backend() {
        let Some(token) = crate::x86::AesNi::detect() else {
            return;
        };

        for key_len in [16, 24, 32] {
            let key: [u8; 32] =
                core::array::from_fn(|index| (index as u8).wrapping_mul(0x3d).wrapping_add(0x17));
            let rounds = cipher::rounds_for(key_len).unwrap();
            let round_keys = cipher::expand_key(&key[..key_len], rounds);

            let mut portable_decryption_keys = round_keys;
            cipher::prepare_decryption_keys(&mut portable_decryption_keys, rounds);
            let mut accelerated_decryption_keys = round_keys;
            token.prepare_decryption_keys(&mut accelerated_decryption_keys, rounds);

            for case in 0..32_u8 {
                let input: [u8; BLOCK_BYTES] = core::array::from_fn(|index| {
                    case.wrapping_mul(0x29).wrapping_add(index as u8 * 0x0b)
                });

                let mut portable_ciphertext = [0_u8; BLOCK_BYTES];
                let mut accelerated_ciphertext = [0_u8; BLOCK_BYTES];
                cipher::encrypt_block(&round_keys, rounds, &input, &mut portable_ciphertext);
                token.encrypt_block(&round_keys, rounds, &input, &mut accelerated_ciphertext);
                assert_eq!(accelerated_ciphertext, portable_ciphertext, "key {key_len}");

                let mut portable_plaintext = [0_u8; BLOCK_BYTES];
                let mut accelerated_plaintext = [0_u8; BLOCK_BYTES];
                cipher::decrypt_block(
                    &portable_decryption_keys,
                    rounds,
                    &portable_ciphertext,
                    &mut portable_plaintext,
                );
                token.decrypt_block(
                    &accelerated_decryption_keys,
                    rounds,
                    &portable_ciphertext,
                    &mut accelerated_plaintext,
                );
                assert_eq!(portable_plaintext, input, "key {key_len}");
                assert_eq!(accelerated_plaintext, input, "key {key_len}");
            }
        }
    }
}
