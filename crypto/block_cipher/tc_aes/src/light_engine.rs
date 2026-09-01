//! Small-footprint AES engine, following Bouncy Castle's `AesLightEngine`.

use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::BLOCK_BYTES;
use crate::cipher::{self, INVERSE_S_BOX, S_BOX};

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

/// Applies AES MixColumns to four bytes packed into a little-endian word.
#[inline]
const fn mcol(value: u32) -> u32 {
    let t0 = value.rotate_right(8);
    let t1 = value ^ t0;
    t1.rotate_right(16) ^ t0 ^ ff_mul_x(t1)
}

/// Applies AES inverse MixColumns to four packed bytes.
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

/// Expands the key into the working key for one direction.
///
/// Unlike the T-table backend, decryption folds the inverse MixColumns into the
/// schedule here, so the block path needs no separate preparation step.
fn generate_working_key(key: &[u8], rounds: usize, for_encryption: bool) -> WorkingKey {
    let key_words = key.len() / 4;
    let total_words = (rounds + 1) * 4;
    let mut working_key = [0_u32; MAX_WORKING_KEY_WORDS];

    for (word, bytes) in working_key.iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().unwrap());
    }

    let mut rcon = 1_u8;
    for index in key_words..total_words {
        let mut temp = working_key[index - 1];
        if index.is_multiple_of(key_words) {
            temp = sub_word(temp.rotate_right(8)) ^ u32::from(rcon);
            rcon = (rcon << 1) ^ (0x1b & 0_u8.wrapping_sub(rcon >> 7));
        } else if key_words == 8 && index % key_words == 4 {
            temp = sub_word(temp);
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
    let mut state = [0_u32; 4];
    for (column, bytes) in state.iter_mut().zip(input.chunks_exact(4)) {
        *column = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    state
}

fn store_state(state: &[u32; 4], output: &mut [u8; BLOCK_BYTES]) {
    for (word, chunk) in state.iter().zip(output.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&word.to_le_bytes());
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

    // 最後一輪沒有 MixColumns。
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

/// AES in the small-footprint representation.
///
/// The state is four `u32` words, only the 256-byte S-box and its inverse are
/// used, and `MixColumns` is computed each round rather than looked up. This
/// never touches the 2 KiB T-tables of [`AesEngine`], and never selects AES-NI.
///
/// [`AesEngine`]: crate::AesEngine
pub struct AesLightEngine {
    working_key: WorkingKey,
    rounds: usize,
    for_encryption: bool,
    initialised: bool,
}

impl AesLightEngine {
    /// Creates an uninitialised light AES engine.
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

impl AlgorithmName for AesLightEngine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("AES")
    }
}

impl BlockCipher for AesLightEngine {
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
        if self.for_encryption {
            encrypt_block(&self.working_key, self.rounds, input, output);
        } else {
            decrypt_block(&self.working_key, self.rounds, input, output);
        }
        Ok(BLOCK_BYTES)
    }
}

impl BlockCipherInit for AesLightEngine {
    type Params<'a> = dyn KeyParams + 'a;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), InitError> {
        let key = params.key();
        let rounds = cipher::rounds_for(key.len()).ok_or(InitError::InvalidKeyLength(key.len()))?;

        let for_encryption = direction == CipherDirection::Encrypt;
        self.working_key = generate_working_key(key, rounds, for_encryption);
        self.rounds = rounds;
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mix_columns_has_a_working_inverse() {
        for value in [0, 1, u32::MAX, 0x0302_0100, 0xa5c3_7e19] {
            assert_eq!(inverse_mcol(mcol(value)), value);
        }
    }

    /// The light representation has to agree with the T-table one, since the
    /// two are offered as interchangeable implementations of the same cipher.
    #[test]
    fn the_light_representation_matches_the_t_table_one() {
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        for key_len in [16, 24, 32] {
            let key: [u8; 32] =
                core::array::from_fn(|index| (index as u8).wrapping_mul(0x3d).wrapping_add(0x17));
            let key = &key[..key_len];
            let rounds = cipher::rounds_for(key_len).unwrap();

            let mut light_ciphertext = [0_u8; BLOCK_BYTES];
            encrypt_block(
                &generate_working_key(key, rounds, true),
                rounds,
                &plaintext,
                &mut light_ciphertext,
            );

            let round_keys = cipher::expand_key(key, rounds);
            let mut table_ciphertext = [0_u8; BLOCK_BYTES];
            cipher::encrypt_block(&round_keys, rounds, &plaintext, &mut table_ciphertext);
            assert_eq!(light_ciphertext, table_ciphertext, "key length {key_len}");

            let mut recovered = [0_u8; BLOCK_BYTES];
            decrypt_block(
                &generate_working_key(key, rounds, false),
                rounds,
                &light_ciphertext,
                &mut recovered,
            );
            assert_eq!(recovered, plaintext, "key length {key_len}");
        }
    }
}
