//! AES on the x86 AES-NI instructions. Only x86 and x86_64 targets have this
//! engine.

#[cfg(target_arch = "x86")]
use core::arch::x86::{
    __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128, _mm_aesenclast_si128,
    _mm_aesimc_si128, _mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128,
};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128, _mm_aesenclast_si128,
    _mm_aesimc_si128, _mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128,
};

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_runtime::intrinsics::x86::{Aes, Sse2};
use tc_zeroize::Zeroize;

use crate::BLOCK_BYTES;
use crate::common::{MAX_ROUND_KEYS, RoundKeys, expand_key, rounds_for};

/// Proof, from `tc_runtime`, that AES-NI and SSE2 are available and not
/// disabled.
///
/// Only [`AesNi::detect`] makes one, so code holding a token has established
/// support and may call the intrinsics below; the `unsafe` stays in this file.
#[derive(Clone, Copy)]
struct AesNi {
    _aes: Aes,
    _sse2: Sse2,
}

impl AesNi {
    /// Branches only on the processor's capabilities, which `tc_runtime`
    /// caches.
    fn detect() -> Option<Self> {
        Some(Self {
            _aes: Aes::detect()?,
            _sse2: Sse2::detect()?,
        })
    }

    fn prepare_decryption_keys(self, round_keys: &mut RoundKeys, rounds: usize) {
        // SAFETY: holding `self` proves AES-NI and SSE2 support.
        unsafe { prepare_decryption_keys(round_keys, rounds) }
    }

    fn encrypt_block(
        self,
        round_keys: &RoundKeys,
        rounds: usize,
        input: &[u8; BLOCK_BYTES],
        output: &mut [u8; BLOCK_BYTES],
    ) {
        // SAFETY: holding `self` proves AES-NI and SSE2 support.
        unsafe { encrypt_block(round_keys, rounds, input, output) }
    }

    fn decrypt_block(
        self,
        round_keys: &RoundKeys,
        rounds: usize,
        input: &[u8; BLOCK_BYTES],
        output: &mut [u8; BLOCK_BYTES],
    ) {
        // SAFETY: holding `self` proves AES-NI and SSE2 support.
        unsafe { decrypt_block(round_keys, rounds, input, output) }
    }
}

/// # Safety
///
/// The caller must establish SSE2 support.
#[inline]
unsafe fn load(value: &[u8; BLOCK_BYTES]) -> __m128i {
    // SAFETY: an unaligned load of 16 readable bytes; SSE2 is the caller's.
    unsafe { _mm_loadu_si128(value.as_ptr().cast()) }
}

/// Reverses the round keys and applies AESIMC to the inner ones, the form
/// the equivalent inverse cipher expects.
///
/// # Safety
///
/// The caller must establish AES-NI and SSE2 support.
#[target_feature(enable = "aes,sse2")]
unsafe fn prepare_decryption_keys(round_keys: &mut RoundKeys, rounds: usize) {
    let mut encryption_keys = *round_keys;
    round_keys[0] = encryption_keys[rounds];
    for round in 1..rounds {
        // SAFETY: AES-NI and SSE2 are the caller's; both pointers cover 16 bytes.
        unsafe {
            let key = _mm_aesimc_si128(load(&encryption_keys[rounds - round]));
            _mm_storeu_si128(round_keys[round].as_mut_ptr().cast(), key);
        }
    }
    round_keys[rounds] = encryption_keys[0];
    encryption_keys.zeroize();
}

/// # Safety
///
/// The caller must establish AES-NI and SSE2 support.
#[target_feature(enable = "aes,sse2")]
unsafe fn encrypt_block(
    round_keys: &RoundKeys,
    rounds: usize,
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) {
    // SAFETY: AES-NI and SSE2 are the caller's; every pointer covers 16 bytes.
    unsafe {
        let mut state = _mm_xor_si128(load(input), load(&round_keys[0]));
        for round_key in &round_keys[1..rounds] {
            state = _mm_aesenc_si128(state, load(round_key));
        }
        state = _mm_aesenclast_si128(state, load(&round_keys[rounds]));
        _mm_storeu_si128(output.as_mut_ptr().cast(), state);
    }
}

/// # Safety
///
/// The caller must establish AES-NI and SSE2 support.
#[target_feature(enable = "aes,sse2")]
unsafe fn decrypt_block(
    round_keys: &RoundKeys,
    rounds: usize,
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) {
    // SAFETY: AES-NI and SSE2 are the caller's; every pointer covers 16 bytes.
    unsafe {
        let mut state = _mm_xor_si128(load(input), load(&round_keys[0]));
        for round_key in &round_keys[1..rounds] {
            state = _mm_aesdec_si128(state, load(round_key));
        }
        state = _mm_aesdeclast_si128(state, load(&round_keys[rounds]));
        _mm_storeu_si128(output.as_mut_ptr().cast(), state);
    }
}

/// AES on the AES-NI instructions, where the processor has them.
///
/// Constant time: the rounds are single instructions whose timing does not
/// depend on their operands, and the key schedule computes the S-box rather
/// than looking it up. The round keys are wiped on drop, but copies left in
/// registers or on the stack are not.
///
/// Use [`new`](Self::new) to check availability and construct an engine.
/// It returns `None` when this backend is unavailable.
///
/// # Example
///
/// Handle unavailable or disabled AES-NI explicitly.
///
/// ```
/// use tc_aes::AesX86Engine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
///
/// let Some(mut engine) = AesX86Engine::new() else {
///     // Let the caller choose a fallback or report unsupported hardware.
///     return Ok(());
/// };
/// let key = [0x42; 32];
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut output = [0; 16];
/// assert_eq!(engine.process_block(&[0; 16], &mut output)?, 16);
/// assert_eq!(engine.to_string(), "AES");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct AesX86Engine {
    token: AesNi,
    round_keys: RoundKeys,
    rounds: usize,
    for_encryption: bool,
    initialised: bool,
}

impl core::fmt::Display for AesX86Engine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(crate::ALGO_NAME)
    }
}

impl AesX86Engine {
    /// An engine without a key, or `None` when this backend is unavailable;
    /// `init` must come before `process_block`.
    /// Branches only on those public facts.
    pub fn new() -> Option<Self> {
        AesNi::detect().map(|token| Self {
            token,
            round_keys: [[0; BLOCK_BYTES]; MAX_ROUND_KEYS],
            rounds: 0,
            for_encryption: false,
            initialised: false,
        })
    }

    /// Whether [`new`](Self::new) returns an engine.
    pub fn is_supported() -> bool {
        AesNi::detect().is_some()
    }
}

impl Drop for AesX86Engine {
    fn drop(&mut self) {
        self.round_keys.zeroize();
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for AesX86Engine {
    type Error = InitError;

    /// Expands a 16-, 24- or 32-byte key. Constant time; branches only on the
    /// key length and direction. A rejected key leaves the previous state in
    /// place.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let rounds = rounds_for(key.len()).ok_or(InitError::InvalidKeyLength(key.len()))?;
        let for_encryption = direction == CipherDirection::Encrypt;
        self.round_keys = expand_key(key, rounds);
        if !for_encryption {
            self.token
                .prepare_decryption_keys(&mut self.round_keys, rounds);
        }
        self.rounds = rounds;
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }
}

impl BlockCipher for AesX86Engine {
    type Error = BlockError;

    /// Always 16. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Transforms the first 16 bytes of `input` into the first 16 of
    /// `output`. Constant time in the key and the data.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }
        let (Some(input), Some(output)) = (
            input.first_chunk::<BLOCK_BYTES>(),
            output.first_chunk_mut::<BLOCK_BYTES>(),
        ) else {
            return Err(BlockError::BufferTooShort);
        };
        if self.for_encryption {
            self.token
                .encrypt_block(&self.round_keys, self.rounds, input, output);
        } else {
            self.token
                .decrypt_block(&self.round_keys, self.rounds, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::AesX86Engine;
    use crate::common::test_support as support;
    use crate::{AesLightEngine, AesTableEngine};

    /// The engine, for a processor the test has checked; each test returns
    /// early where AES-NI is missing.
    fn engine() -> AesX86Engine {
        AesX86Engine::new().expect("checked by is_supported")
    }

    #[test]
    fn new_returns_an_engine_exactly_when_the_processor_is_supported() {
        assert_eq!(AesX86Engine::new().is_some(), AesX86Engine::is_supported());
    }

    #[test]
    fn fips_197_vectors_encrypt_and_decrypt_under_every_key_size() {
        if AesX86Engine::is_supported() {
            support::check_fips_197(engine);
        }
    }

    #[test]
    fn processing_before_init_is_rejected() {
        if AesX86Engine::is_supported() {
            support::check_uninitialised(engine);
        }
    }

    #[test]
    fn short_buffers_are_rejected_and_longer_ones_get_exactly_one_block() {
        if AesX86Engine::is_supported() {
            support::check_buffers(engine);
        }
    }

    #[test]
    fn a_rejected_key_length_keeps_the_previous_key() {
        if AesX86Engine::is_supported() {
            support::check_rejected_key(engine);
        }
    }

    #[test]
    fn the_x86_engine_agrees_with_the_portable_engines_on_pseudorandom_keys_and_blocks() {
        if AesX86Engine::is_supported() {
            support::check_agreement(engine, AesTableEngine::new);
            support::check_agreement(engine, AesLightEngine::new);
        }
    }

    #[cfg(feature = "rustcrypto")]
    #[test]
    fn the_x86_engine_agrees_with_rustcrypto_on_pseudorandom_keys_and_blocks() {
        if AesX86Engine::is_supported() {
            support::check_against_rustcrypto(engine);
        }
    }
}
