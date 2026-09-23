//! Small-footprint AES, following Bouncy Castle's `AesLightEngine`.

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::BLOCK_BYTES;
use crate::common::{INVERSE_S_BOX, S_BOX, rounds_for};

/// Working-key words for the longest schedule (AES-256).
const MAX_WORKING_KEY_WORDS: usize = 60;
type WorkingKey = [u32; MAX_WORKING_KEY_WORDS];

const M1: u32 = 0x8080_8080;
const M2: u32 = 0x7f7f_7f7f;
const M3: u32 = 0x0000_001b;
const M4: u32 = 0xc0c0_c0c0;
const M5: u32 = 0x3f3f_3f3f;

#[inline]
const fn ff_mul_x(value: u32) -> u32 {
    ((value & M2) << 1) ^ (((value & M1) >> 7) * M3)
}

#[inline]
const fn ff_mul_x2(value: u32) -> u32 {
    let t0 = (value & M5) << 2;
    let mut t1 = value & M4;
    t1 ^= t1 >> 1;
    t0 ^ (t1 >> 2) ^ (t1 >> 5)
}

/// MixColumns on four bytes packed into a little-endian word.
#[inline]
const fn mcol(value: u32) -> u32 {
    let t0 = value.rotate_right(8);
    let t1 = value ^ t0;
    t1.rotate_right(16) ^ t0 ^ ff_mul_x(t1)
}

/// Inverse MixColumns on four packed bytes.
#[inline]
const fn inverse_mcol(value: u32) -> u32 {
    let mut t0 = value;
    let mut t1 = t0 ^ t0.rotate_right(8);
    t0 ^= ff_mul_x(t1);
    t1 ^= ff_mul_x2(t0);
    t0 ^ t1 ^ t1.rotate_right(16)
}

#[inline]
fn sub_word(value: u32) -> u32 {
    let mut bytes = value.to_le_bytes();
    for byte in &mut bytes {
        *byte = S_BOX[usize::from(*byte)];
    }
    u32::from_le_bytes(bytes)
}

/// The key schedule for one direction. Decryption folds inverse MixColumns
/// into the schedule, so the block path needs no separate preparation.
fn generate_working_key(key: &[u8], rounds: usize, for_encryption: bool) -> WorkingKey {
    let key_words = key.len() / 4;
    let total_words = (rounds + 1) * 4;
    let mut working_key = [0_u32; MAX_WORKING_KEY_WORDS];

    for (index, word) in working_key.iter_mut().take(key_words).enumerate() {
        let at = index * 4;
        *word = u32::from_le_bytes([key[at], key[at + 1], key[at + 2], key[at + 3]]);
    }

    let mut rcon = 1_u8;
    for index in key_words..total_words {
        let mut temp = working_key[index - 1];
        match index % key_words {
            0 => {
                temp = sub_word(temp.rotate_right(8)) ^ u32::from(rcon);
                rcon = (rcon << 1) ^ (0x1b & 0_u8.wrapping_sub(rcon >> 7));
            }
            4 if key_words == 8 => temp = sub_word(temp),
            _ => {}
        }
        working_key[index] = working_key[index - key_words] ^ temp;
    }

    if !for_encryption {
        for word in &mut working_key[4..rounds * 4] {
            *word = inverse_mcol(*word);
        }
    }

    working_key
}

#[inline]
fn substitute_shift_rows(state: &[u32; 4]) -> [u32; 4] {
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
fn inverse_substitute_shift_rows(state: &[u32; 4]) -> [u32; 4] {
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

fn encrypt_block(
    working_key: &WorkingKey,
    rounds: usize,
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) {
    let mut state = load_state(input);
    for (column, value) in state.iter_mut().enumerate() {
        *value ^= working_key[column];
    }

    for round in 1..rounds {
        let substituted = substitute_shift_rows(&state);
        for (column, value) in state.iter_mut().enumerate() {
            *value = mcol(substituted[column]) ^ working_key[round * 4 + column];
        }
    }

    // The last round has no MixColumns.
    let substituted = substitute_shift_rows(&state);
    for (column, value) in state.iter_mut().enumerate() {
        *value = substituted[column] ^ working_key[rounds * 4 + column];
    }
    store_state(&state, output);
}

fn decrypt_block(
    working_key: &WorkingKey,
    rounds: usize,
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) {
    let mut state = load_state(input);
    for (column, value) in state.iter_mut().enumerate() {
        *value ^= working_key[rounds * 4 + column];
    }

    for round in (1..rounds).rev() {
        let substituted = inverse_substitute_shift_rows(&state);
        for (column, value) in state.iter_mut().enumerate() {
            *value = inverse_mcol(substituted[column]) ^ working_key[round * 4 + column];
        }
    }

    let substituted = inverse_substitute_shift_rows(&state);
    for (column, value) in state.iter_mut().enumerate() {
        *value = substituted[column] ^ working_key[column];
    }
    store_state(&state, output);
}

/// AES in the small-footprint representation: four `u32` words of state,
/// only the 256-byte S-box and its inverse, and MixColumns computed rather
/// than looked up.
///
/// **Variable time.** The S-box lookups are indexed by bytes that depend on
/// the key and the data, so cache timing can leak both. Use it only where
/// that side channel is out of scope; `AesRustCryptoEngine` and
/// `AesX86Engine` are constant time. The working key is wiped on drop, but
/// copies left on the stack while it is built are not.
///
/// # Example
///
/// Choose this engine for its smaller lookup tables, not constant-time processing.
///
/// ```
/// use tc_aes::AesLightEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
///
/// let mut engine = AesLightEngine::new();
/// let key = [0x42; 32];
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut output = [0; 16];
/// assert_eq!(engine.process_block(&[0; 16], &mut output)?, 16);
/// assert_eq!(engine.to_string(), "AES");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct AesLightEngine {
    working_key: WorkingKey,
    rounds: usize,
    for_encryption: bool,
    initialised: bool,
}

impl core::fmt::Display for AesLightEngine {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(crate::ALGO_NAME)
    }
}

impl AesLightEngine {
    /// An engine without a key; `init` must come before `process_block`.
    /// Constant time.
    pub const fn new() -> Self {
        Self {
            working_key: [0; MAX_WORKING_KEY_WORDS],
            rounds: 0,
            for_encryption: false,
            initialised: false,
        }
    }
}

impl Default for AesLightEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AesLightEngine {
    fn drop(&mut self) {
        self.working_key.zeroize();
    }
}

impl<P: KeyParams + ?Sized> BlockCipherInit<P> for AesLightEngine {
    type Error = InitError;

    /// Expands a 16-, 24- or 32-byte key. Variable time: the schedule looks
    /// up the S-box by key bytes. A rejected key leaves the previous state in
    /// place.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        let rounds = rounds_for(key.len()).ok_or(InitError::InvalidKeyLength(key.len()))?;
        let for_encryption = direction == CipherDirection::Encrypt;
        self.working_key = generate_working_key(key, rounds, for_encryption);
        self.rounds = rounds;
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }
}

impl BlockCipher for AesLightEngine {
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
            encrypt_block(&self.working_key, self.rounds, input, output);
        } else {
            decrypt_block(&self.working_key, self.rounds, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::{AesLightEngine, inverse_mcol, mcol};
    use crate::common::test_support as support;

    #[test]
    fn mix_columns_has_a_working_inverse() {
        for value in [0, 1, u32::MAX, 0x0302_0100, 0xa5c3_7e19] {
            assert_eq!(inverse_mcol(mcol(value)), value);
        }
    }

    #[test]
    fn fips_197_vectors_encrypt_and_decrypt_under_every_key_size() {
        support::check_fips_197(AesLightEngine::new);
    }

    #[test]
    fn processing_before_init_is_rejected() {
        support::check_uninitialised(AesLightEngine::new);
    }

    #[test]
    fn short_buffers_are_rejected_and_longer_ones_get_exactly_one_block() {
        support::check_buffers(AesLightEngine::new);
    }

    #[test]
    fn a_rejected_key_length_keeps_the_previous_key() {
        support::check_rejected_key(AesLightEngine::new);
    }

    #[cfg(feature = "rustcrypto")]
    #[test]
    fn the_light_engine_agrees_with_rustcrypto_on_pseudorandom_keys_and_blocks() {
        support::check_against_rustcrypto(AesLightEngine::new);
    }
}
