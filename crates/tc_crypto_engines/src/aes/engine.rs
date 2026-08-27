//! AES engine and runtime backend dispatch.

use tc_crypto_core::BlockCipher;

use super::{AES_BLOCK_BYTES, AesError, AesParams, RoundKeys, portable};

#[derive(Clone, Copy)]
enum Backend {
    Portable,
    #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
    AesNi,
}

fn detect_backend() -> Backend {
    #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
    if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2") {
        return Backend::AesNi;
    }
    Backend::Portable
}

/// AES block cipher with portable and x86 AES-NI backends.
pub struct AesEngine {
    round_keys: RoundKeys,
    rounds: usize,
    for_encryption: bool,
    initialised: bool,
    backend: Backend,
}

impl AesEngine {
    /// Creates an uninitialised AES engine and selects the best available backend.
    pub fn new() -> Self {
        Self {
            round_keys: [[0u8; AES_BLOCK_BYTES]; 15],
            rounds: 0,
            for_encryption: false,
            initialised: false,
            backend: detect_backend(),
        }
    }

    fn transform(&self, input: &[u8; AES_BLOCK_BYTES], output: &mut [u8; AES_BLOCK_BYTES]) {
        match (self.backend, self.for_encryption) {
            (Backend::Portable, true) => {
                portable::encrypt_block(&self.round_keys, self.rounds, input, output)
            }
            (Backend::Portable, false) => {
                portable::decrypt_block(&self.round_keys, self.rounds, input, output)
            }
            #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
            (Backend::AesNi, true) => {
                // SAFETY: `Backend::AesNi` is created only after runtime detection.
                unsafe { super::x86::encrypt_block(&self.round_keys, self.rounds, input, output) }
            }
            #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
            (Backend::AesNi, false) => {
                // SAFETY: `Backend::AesNi` is created only after runtime detection.
                unsafe { super::x86::decrypt_block(&self.round_keys, self.rounds, input, output) }
            }
        }
    }
}

impl Default for AesEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for AesEngine {
    type Params<'a> = AesParams;
    type Error = AesError;

    fn algorithm_name(&self) -> &str {
        "AES"
    }

    fn block_size(&self) -> usize {
        AES_BLOCK_BYTES
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        (self.round_keys, self.rounds) = portable::expand_key(params.key());
        self.for_encryption = for_encryption;

        #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
        if matches!(self.backend, Backend::AesNi) && !for_encryption {
            // SAFETY: `Backend::AesNi` is created only after runtime detection.
            unsafe { super::x86::prepare_decryption_keys(&mut self.round_keys, self.rounds) };
        }

        self.initialised = true;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(AesError::NotInitialised);
        }
        if input.len() < AES_BLOCK_BYTES || output.len() < AES_BLOCK_BYTES {
            return Err(AesError::BufferTooShort);
        }

        let input: &[u8; AES_BLOCK_BYTES] = input[..AES_BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; AES_BLOCK_BYTES] =
            (&mut output[..AES_BLOCK_BYTES]).try_into().unwrap();
        self.transform(input, output);
        Ok(AES_BLOCK_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_processing_errors() {
        let mut engine = AesEngine::new();
        assert_eq!(engine.algorithm_name(), "AES");
        assert_eq!(engine.block_size(), AES_BLOCK_BYTES);
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 16]),
            Err(AesError::NotInitialised)
        );

        engine
            .init(true, &AesParams::new(&[0u8; 16]).unwrap())
            .unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 15], &mut [0u8; 16]),
            Err(AesError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 15]),
            Err(AesError::BufferTooShort)
        );
    }

    #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
    #[test]
    fn aes_ni_matches_portable() {
        if !std::is_x86_feature_detected!("aes") || !std::is_x86_feature_detected!("sse2") {
            return;
        }

        for key_len in [16, 24, 32] {
            let key: alloc::vec::Vec<u8> = (0..key_len)
                .map(|index| (index as u8).wrapping_mul(0x3D).wrapping_add(0x17))
                .collect();
            let (round_keys, rounds) = portable::expand_key(&key);
            for case in 0..32u8 {
                let mut input = [0u8; AES_BLOCK_BYTES];
                for (index, value) in input.iter_mut().enumerate() {
                    *value = case.wrapping_mul(0x29).wrapping_add(index as u8 * 0x0B);
                }

                let mut portable_ciphertext = [0u8; AES_BLOCK_BYTES];
                let mut accelerated_ciphertext = [0u8; AES_BLOCK_BYTES];
                portable::encrypt_block(&round_keys, rounds, &input, &mut portable_ciphertext);
                // SAFETY: AES and SSE2 support were detected above.
                unsafe {
                    super::super::x86::encrypt_block(
                        &round_keys,
                        rounds,
                        &input,
                        &mut accelerated_ciphertext,
                    )
                };
                assert_eq!(accelerated_ciphertext, portable_ciphertext);

                let mut portable_plaintext = [0u8; AES_BLOCK_BYTES];
                let mut accelerated_plaintext = [0u8; AES_BLOCK_BYTES];
                portable::decrypt_block(
                    &round_keys,
                    rounds,
                    &portable_ciphertext,
                    &mut portable_plaintext,
                );
                let mut decryption_keys = round_keys;
                // SAFETY: AES and SSE2 support were detected above.
                unsafe {
                    super::super::x86::prepare_decryption_keys(&mut decryption_keys, rounds);
                    super::super::x86::decrypt_block(
                        &decryption_keys,
                        rounds,
                        &portable_ciphertext,
                        &mut accelerated_plaintext,
                    )
                };
                assert_eq!(portable_plaintext, input);
                assert_eq!(accelerated_plaintext, input);
            }
        }
    }
}
