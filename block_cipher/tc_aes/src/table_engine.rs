//! Portable AES with one forward and one inverse T-table, following Bouncy
//! Castle's `AesEngine`.

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::BLOCK_BYTES;
use crate::common::{
    INVERSE_S_BOX, MAX_ROUND_KEYS, RoundKeys, S_BOX, expand_key, gf_mul, rounds_for,
};

const fn build_t0() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let value = S_BOX[index];
        let x = gf_mul(value, 2);
        table[index] = u32::from_le_bytes([x, value, value, x ^ value]);
        index += 1;
    }
    table
}

const fn build_inverse_t0() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let value = INVERSE_S_BOX[index];
        table[index] = u32::from_le_bytes([
            gf_mul(value, 14),
            gf_mul(value, 9),
            gf_mul(value, 13),
            gf_mul(value, 11),
        ]);
        index += 1;
    }
    table
}

/// SubBytes and MixColumns for one column byte; the other three columns are
/// rotations of it.
static T0: [u32; 256] = build_t0();
static INVERSE_T0: [u32; 256] = build_inverse_t0();

#[inline]
fn round_key_word(round_keys: &RoundKeys, round: usize, column: usize) -> u32 {
    let key = &round_keys[round];
    let at = column * 4;
    u32::from_le_bytes([key[at], key[at + 1], key[at + 2], key[at + 3]])
}

const fn inverse_mix_word(value: u32) -> u32 {
    let b = value.to_le_bytes();
    u32::from_le_bytes([
        gf_mul(b[0], 14) ^ gf_mul(b[1], 11) ^ gf_mul(b[2], 13) ^ gf_mul(b[3], 9),
        gf_mul(b[0], 9) ^ gf_mul(b[1], 14) ^ gf_mul(b[2], 11) ^ gf_mul(b[3], 13),
        gf_mul(b[0], 13) ^ gf_mul(b[1], 9) ^ gf_mul(b[2], 14) ^ gf_mul(b[3], 11),
        gf_mul(b[0], 11) ^ gf_mul(b[1], 13) ^ gf_mul(b[2], 9) ^ gf_mul(b[3], 14),
    ])
}

/// Applies inverse MixColumns to the inner round keys, for the equivalent
/// inverse cipher of FIPS 197 §5.3.5.
fn prepare_decryption_keys(round_keys: &mut RoundKeys, rounds: usize) {
    for round_key in &mut round_keys[1..rounds] {
        for column in 0..4 {
            let at = column * 4;
            let word = u32::from_le_bytes([
                round_key[at],
                round_key[at + 1],
                round_key[at + 2],
                round_key[at + 3],
            ]);
            round_key[at..at + 4].copy_from_slice(&inverse_mix_word(word).to_le_bytes());
        }
    }
}

fn load_state(input: &[u8; BLOCK_BYTES]) -> [u32; 4] {
    core::array::from_fn(|column| {
        let at = column * 4;
        u32::from_le_bytes([input[at], input[at + 1], input[at + 2], input[at + 3]])
    })
}

fn store_state(state: &[u32; 4], output: &mut [u8; BLOCK_BYTES]) {
    for (column, word) in state.iter().enumerate() {
        output[column * 4..column * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
}

#[inline]
fn encrypt_round(state: &[u32; 4]) -> [u32; 4] {
    let t = |word: usize, shift: u32, rotate: u32| {
        T0[((state[word] >> shift) & 0xff) as usize].rotate_right(rotate)
    };
    [
        t(0, 0, 0) ^ t(1, 8, 24) ^ t(2, 16, 16) ^ t(3, 24, 8),
        t(1, 0, 0) ^ t(2, 8, 24) ^ t(3, 16, 16) ^ t(0, 24, 8),
        t(2, 0, 0) ^ t(3, 8, 24) ^ t(0, 16, 16) ^ t(1, 24, 8),
        t(3, 0, 0) ^ t(0, 8, 24) ^ t(1, 16, 16) ^ t(2, 24, 8),
    ]
}

#[inline]
fn decrypt_round(state: &[u32; 4]) -> [u32; 4] {
    let t = |word: usize, shift: u32, rotate: u32| {
        INVERSE_T0[((state[word] >> shift) & 0xff) as usize].rotate_right(rotate)
    };
    [
        t(0, 0, 0) ^ t(3, 8, 24) ^ t(2, 16, 16) ^ t(1, 24, 8),
        t(1, 0, 0) ^ t(0, 8, 24) ^ t(3, 16, 16) ^ t(2, 24, 8),
        t(2, 0, 0) ^ t(1, 8, 24) ^ t(0, 16, 16) ^ t(3, 24, 8),
        t(3, 0, 0) ^ t(2, 8, 24) ^ t(1, 16, 16) ^ t(0, 24, 8),
    ]
}

#[inline]
fn final_encrypt_round(state: &[u32; 4]) -> [u32; 4] {
    let s = |word: usize, shift: u32| -> u32 {
        u32::from(S_BOX[((state[word] >> shift) & 0xff) as usize]) << shift
    };
    [
        s(0, 0) ^ s(1, 8) ^ s(2, 16) ^ s(3, 24),
        s(1, 0) ^ s(2, 8) ^ s(3, 16) ^ s(0, 24),
        s(2, 0) ^ s(3, 8) ^ s(0, 16) ^ s(1, 24),
        s(3, 0) ^ s(0, 8) ^ s(1, 16) ^ s(2, 24),
    ]
}

#[inline]
fn final_decrypt_round(state: &[u32; 4]) -> [u32; 4] {
    let s = |word: usize, shift: u32| -> u32 {
        u32::from(INVERSE_S_BOX[((state[word] >> shift) & 0xff) as usize]) << shift
    };
    [
        s(0, 0) ^ s(3, 8) ^ s(2, 16) ^ s(1, 24),
        s(1, 0) ^ s(0, 8) ^ s(3, 16) ^ s(2, 24),
        s(2, 0) ^ s(1, 8) ^ s(0, 16) ^ s(3, 24),
        s(3, 0) ^ s(2, 8) ^ s(1, 16) ^ s(0, 24),
    ]
}

fn encrypt_block(
    round_keys: &RoundKeys,
    rounds: usize,
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) {
    let mut state = load_state(input);
    for (column, value) in state.iter_mut().enumerate() {
        *value ^= round_key_word(round_keys, 0, column);
    }
    for round in 1..rounds {
        state = encrypt_round(&state);
        for (column, value) in state.iter_mut().enumerate() {
            *value ^= round_key_word(round_keys, round, column);
        }
    }
    state = final_encrypt_round(&state);
    for (column, value) in state.iter_mut().enumerate() {
        *value ^= round_key_word(round_keys, rounds, column);
    }
    store_state(&state, output);
}

fn decrypt_block(
    round_keys: &RoundKeys,
    rounds: usize,
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) {
    let mut state = load_state(input);
    for (column, value) in state.iter_mut().enumerate() {
        *value ^= round_key_word(round_keys, rounds, column);
    }
    for round in (1..rounds).rev() {
        state = decrypt_round(&state);
        for (column, value) in state.iter_mut().enumerate() {
            *value ^= round_key_word(round_keys, round, column);
        }
    }
    state = final_decrypt_round(&state);
    for (column, value) in state.iter_mut().enumerate() {
        *value ^= round_key_word(round_keys, 0, column);
    }
    store_state(&state, output);
}

/// AES with a 1 KiB forward and a 1 KiB inverse T-table: the fastest of the
/// portable engines.
///
/// **Variable time.** Every round looks up the T-tables by bytes that depend
/// on the key and the data, the textbook cache-timing target, so the key can
/// leak. Use it only where that side channel is out of scope;
/// `AesRustCryptoEngine` and `AesX86Engine` are constant time. The key
/// schedule itself is constant time. The round keys are wiped on drop, but
/// copies left in registers or on the stack are not.
///
/// # Example
///
/// Choose this engine only when its cache-timing leakage is acceptable.
///
/// ```
/// use tc_aes::AesTableEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
///
/// let mut engine = AesTableEngine::new();
/// let key = [0x42; 32];
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut output = [0; 16];
/// assert_eq!(engine.process_block(&[0; 16], &mut output)?, 16);
/// assert_eq!(engine.to_string(), "AES");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct AesTableEngine {
    round_keys: RoundKeys,
    rounds: usize,
    for_encryption: bool,
    initialised: bool,
}

impl core::fmt::Display for AesTableEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(crate::ALGO_NAME)
    }
}

impl AesTableEngine {
    /// An engine without a key; `init` must come before `process_block`.
    /// Constant time.
    pub const fn new() -> Self {
        Self {
            round_keys: [[0; BLOCK_BYTES]; MAX_ROUND_KEYS],
            rounds: 0,
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for AesTableEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AesTableEngine {
    fn drop(&mut self) {
        self.round_keys.zeroize();
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for AesTableEngine {
    type Error = InitError;

    /// Expands a 16-, 24- or 32-byte key. Constant time: the schedule
    /// computes the S-box rather than looking it up; only the blocks are
    /// variable time. A rejected key leaves the previous state in place.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let rounds = rounds_for(key.len()).ok_or(InitError::InvalidKeyLength(key.len()))?;
        let for_encryption = direction == CipherDirection::Encrypt;
        self.round_keys = expand_key(key, rounds);
        if !for_encryption {
            prepare_decryption_keys(&mut self.round_keys, rounds);
        }
        self.rounds = rounds;
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }
}

impl BlockCipher for AesTableEngine {
    type Error = BlockError;

    /// Always 16. Constant time.
    fn block_size(&self) -> usize {
        BLOCK_BYTES
    }

    /// Transforms the first 16 bytes of `input` into the first 16 of
    /// `output`. Variable time: see the type.
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
            encrypt_block(&self.round_keys, self.rounds, input, output);
        } else {
            decrypt_block(&self.round_keys, self.rounds, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::{AesTableEngine, INVERSE_T0, T0};
    use crate::AesLightEngine;
    use crate::common::test_support as support;

    #[test]
    fn the_generated_t_tables_match_bouncy_castles_first_entries() {
        assert_eq!(T0[0], 0xa563_63c6);
        assert_eq!(INVERSE_T0[0], 0x50a7_f451);
    }

    #[test]
    fn fips_197_vectors_encrypt_and_decrypt_under_every_key_size() {
        support::check_fips_197(AesTableEngine::new);
    }

    #[test]
    fn processing_before_init_is_rejected() {
        support::check_uninitialised(AesTableEngine::new);
    }

    #[test]
    fn short_buffers_are_rejected_and_longer_ones_get_exactly_one_block() {
        support::check_buffers(AesTableEngine::new);
    }

    #[test]
    fn a_rejected_key_length_keeps_the_previous_key() {
        support::check_rejected_key(AesTableEngine::new);
    }

    #[test]
    fn the_table_engine_agrees_with_the_light_engine_on_pseudorandom_keys_and_blocks() {
        support::check_agreement(AesTableEngine::new, AesLightEngine::new);
    }

    #[cfg(feature = "rustcrypto")]
    #[test]
    fn the_table_engine_agrees_with_rustcrypto_on_pseudorandom_keys_and_blocks() {
        support::check_against_rustcrypto(AesTableEngine::new);
    }
}
