//! AES engine and runtime backend dispatch.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::{AES_BLOCK_BYTES, AesParams, BlockCipherError, RoundKeys, portable};

#[derive(Clone, Copy)]
enum Backend {
    Portable,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    AesNi,
}

/// Reports whether this processor offers AES-NI and SSE2.
///
/// 偵測直接讀 CPUID，而非 `std::is_x86_feature_detected!` —— 後者只在 std 才有，
/// 而 CPUID 的取用函式本來就在 `core::arch`，故 no_std 目標一樣能走 AES-NI。
/// 只在建構 engine 時呼叫一次，成本遠低於隨後的金鑰展開，不必快取。
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn has_aes_ni() -> bool {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::{__cpuid, __get_cpuid_max};
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{__cpuid, __get_cpuid_max};

    if __get_cpuid_max(0).0 < 1 {
        return false;
    }
    let leaf1 = __cpuid(1);
    // 基本功能葉：ECX 位元 25 為 AES-NI，EDX 位元 26 為 SSE2。
    (leaf1.ecx & (1 << 25)) != 0 && (leaf1.edx & (1 << 26)) != 0
}

fn detect_backend() -> Backend {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if has_aes_ni() {
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
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            (Backend::AesNi, true) => {
                // SAFETY: `Backend::AesNi` is created only after runtime detection.
                unsafe { super::x86::encrypt_block(&self.round_keys, self.rounds, input, output) }
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
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
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "AES"
    }

    fn block_size(&self) -> usize {
        AES_BLOCK_BYTES
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherError::NotInitialised);
        }
        if input.len() < AES_BLOCK_BYTES || output.len() < AES_BLOCK_BYTES {
            return Err(BlockCipherError::BufferTooShort);
        }

        let input: &[u8; AES_BLOCK_BYTES] = input[..AES_BLOCK_BYTES].try_into().unwrap();
        let output: &mut [u8; AES_BLOCK_BYTES] =
            (&mut output[..AES_BLOCK_BYTES]).try_into().unwrap();
        self.transform(input, output);
        Ok(AES_BLOCK_BYTES)
    }
}

impl BlockCipherInit for AesEngine {
    type Params<'a> = AesParams;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        let for_encryption = direction == CipherDirection::Encrypt;
        (self.round_keys, self.rounds) = portable::expand_key(params.key());
        self.for_encryption = for_encryption;

        if !for_encryption {
            match self.backend {
                Backend::Portable => {
                    portable::prepare_decryption_keys(&mut self.round_keys, self.rounds);
                }
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                Backend::AesNi => {
                    // SAFETY: `Backend::AesNi` is created only after runtime detection.
                    unsafe {
                        super::x86::prepare_decryption_keys(&mut self.round_keys, self.rounds)
                    };
                }
            }
        }

        self.initialised = true;
        Ok(())
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
            Err(BlockCipherError::NotInitialised)
        );

        engine
            .init(
                CipherDirection::Encrypt,
                &AesParams::new(&[0u8; 16]).unwrap(),
            )
            .unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 15], &mut [0u8; 16]),
            Err(BlockCipherError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 15]),
            Err(BlockCipherError::BufferTooShort)
        );
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn aes_ni_matches_portable() {
        if !has_aes_ni() {
            return;
        }

        for key_len in [16, 24, 32] {
            let key: Vec<u8> = (0..key_len)
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
                let mut portable_decryption_keys = round_keys;
                portable::prepare_decryption_keys(&mut portable_decryption_keys, rounds);
                portable::decrypt_block(
                    &portable_decryption_keys,
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
