//! x86/x86_64 AES-NI block transformations.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::{AES_BLOCK_BYTES, RoundKeys};

#[inline]
unsafe fn load(value: &[u8; AES_BLOCK_BYTES]) -> __m128i {
    unsafe { _mm_loadu_si128(value.as_ptr().cast()) }
}

/// Converts encryption round keys into the order and form expected by AESDEC.
///
/// # Safety
///
/// The caller must establish AES and SSE2 support.
#[target_feature(enable = "aes,sse2")]
pub(super) unsafe fn prepare_decryption_keys(round_keys: &mut RoundKeys, rounds: usize) {
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
pub(super) unsafe fn encrypt_block(
    round_keys: &RoundKeys,
    rounds: usize,
    input: &[u8; AES_BLOCK_BYTES],
    output: &mut [u8; AES_BLOCK_BYTES],
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
pub(super) unsafe fn decrypt_block(
    round_keys: &RoundKeys,
    rounds: usize,
    input: &[u8; AES_BLOCK_BYTES],
    output: &mut [u8; AES_BLOCK_BYTES],
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
