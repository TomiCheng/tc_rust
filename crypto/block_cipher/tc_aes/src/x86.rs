//! x86/x86_64 AES-NI backend.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::BLOCK_BYTES;
use crate::cipher::RoundKeys;

/// Proof that this processor offers AES-NI and SSE2.
///
/// The token can only be produced by [`AesNi::detect`], so every caller of the
/// intrinsics below has already established support. That keeps the `unsafe`
/// contract in this file: the engine holds a token and calls safe methods.
#[derive(Clone, Copy)]
pub(crate) struct AesNi(());

impl AesNi {
    /// Returns a token when this processor supports the backend.
    ///
    /// 偵測直接讀 CPUID,而非 `std::is_x86_feature_detected!` —— 後者只在 std 才有,
    /// 而 CPUID 的取用函式本來就在 `core::arch`,故 no_std 目標一樣能走 AES-NI。
    /// 只在建構 engine 時呼叫一次,成本遠低於隨後的金鑰展開,不必快取。
    pub(crate) fn detect() -> Option<Self> {
        if __get_cpuid_max(0).0 < 1 {
            return None;
        }
        let leaf1 = __cpuid(1);
        // 基本功能葉:ECX 位元 25 為 AES-NI,EDX 位元 26 為 SSE2。
        let supported = (leaf1.ecx & (1 << 25)) != 0 && (leaf1.edx & (1 << 26)) != 0;
        supported.then_some(Self(()))
    }

    /// Converts encryption round keys into the order and form AESDEC expects.
    pub(crate) fn prepare_decryption_keys(self, round_keys: &mut RoundKeys, rounds: usize) {
        // SAFETY: holding `self` proves AES and SSE2 support.
        unsafe { prepare_decryption_keys(round_keys, rounds) }
    }

    pub(crate) fn encrypt_block(
        self,
        round_keys: &RoundKeys,
        rounds: usize,
        input: &[u8; BLOCK_BYTES],
        output: &mut [u8; BLOCK_BYTES],
    ) {
        // SAFETY: holding `self` proves AES and SSE2 support.
        unsafe { encrypt_block(round_keys, rounds, input, output) }
    }

    pub(crate) fn decrypt_block(
        self,
        round_keys: &RoundKeys,
        rounds: usize,
        input: &[u8; BLOCK_BYTES],
        output: &mut [u8; BLOCK_BYTES],
    ) {
        // SAFETY: holding `self` proves AES and SSE2 support.
        unsafe { decrypt_block(round_keys, rounds, input, output) }
    }
}

#[inline]
unsafe fn load(value: &[u8; BLOCK_BYTES]) -> __m128i {
    unsafe { _mm_loadu_si128(value.as_ptr().cast()) }
}

/// # Safety
///
/// The caller must establish AES and SSE2 support.
#[target_feature(enable = "aes,sse2")]
unsafe fn prepare_decryption_keys(round_keys: &mut RoundKeys, rounds: usize) {
    unsafe {
        let encryption_keys = *round_keys;
        round_keys[0] = encryption_keys[rounds];
        for round in 1..rounds {
            let key = _mm_aesimc_si128(load(&encryption_keys[rounds - round]));
            _mm_storeu_si128(round_keys[round].as_mut_ptr().cast(), key);
        }
        round_keys[rounds] = encryption_keys[0];
    }
}

/// # Safety
///
/// The caller must establish AES and SSE2 support.
#[target_feature(enable = "aes,sse2")]
unsafe fn encrypt_block(
    round_keys: &RoundKeys,
    rounds: usize,
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) {
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
/// The caller must establish AES and SSE2 support.
#[target_feature(enable = "aes,sse2")]
unsafe fn decrypt_block(
    round_keys: &RoundKeys,
    rounds: usize,
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) {
    unsafe {
        let mut state = _mm_xor_si128(load(input), load(&round_keys[0]));
        for round_key in &round_keys[1..rounds] {
            state = _mm_aesdec_si128(state, load(round_key));
        }
        state = _mm_aesdeclast_si128(state, load(&round_keys[rounds]));
        _mm_storeu_si128(output.as_mut_ptr().cast(), state);
    }
}
