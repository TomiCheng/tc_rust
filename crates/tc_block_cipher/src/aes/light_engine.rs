//! Small-footprint portable AES engine, following Bouncy Castle's
//! `AesLightEngine` representation.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::{
    AES_BLOCK_BYTES, AesParams, BlockCipherError,
    portable::{INVERSE_S_BOX, S_BOX},
};

const MAX_WORKING_KEY_WORDS: usize = 60;
type WorkingKey = [u32; MAX_WORKING_KEY_WORDS];

const M1: u32 = 0x8080_8080;
const M2: u32 = 0x7F7F_7F7F;
const M3: u32 = 0x0000_001B;
const M4: u32 = 0xC0C0_C0C0;
const M5: u32 = 0x3F3F_3F3F;

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
    u32::from_le_bytes([
        S_BOX[value as u8 as usize],
        S_BOX[(value >> 8) as u8 as usize],
        S_BOX[(value >> 16) as u8 as usize],
        S_BOX[(value >> 24) as u8 as usize],
    ])
}

fn generate_working_key(key: &[u8], for_encryption: bool) -> (WorkingKey, usize) {
    let key_words = key.len() / 4;
    let rounds = key_words + 6;
    let total_words = (rounds + 1) * 4;
    let mut working_key = [0u32; MAX_WORKING_KEY_WORDS];

    for (word, bytes) in working_key.iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().unwrap());
    }

    let mut rcon = 1u8;
    for index in key_words..total_words {
        let mut temp = working_key[index - 1];
        if index.is_multiple_of(key_words) {
            temp = sub_word(temp.rotate_right(8)) ^ u32::from(rcon);
            rcon = (rcon << 1) ^ (0x1B & 0u8.wrapping_sub(rcon >> 7));
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

    (working_key, rounds)
}

#[inline]
fn substitute_shift_rows(state: &[u32; 4]) -> [u32; 4] {
    let s = |word: usize, shift: u32| -> u32 {
        u32::from(S_BOX[((state[word] >> shift) & 0xFF) as usize]) << shift
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
        u32::from(INVERSE_S_BOX[((state[word] >> shift) & 0xFF) as usize]) << shift
    };
    [
        s(0, 0) ^ s(3, 8) ^ s(2, 16) ^ s(1, 24),
        s(1, 0) ^ s(0, 8) ^ s(3, 16) ^ s(2, 24),
        s(2, 0) ^ s(1, 8) ^ s(0, 16) ^ s(3, 24),
        s(3, 0) ^ s(2, 8) ^ s(1, 16) ^ s(0, 24),
    ]
}

fn encrypt_block(
    working_key: &WorkingKey,
    rounds: usize,
    input: &[u8; AES_BLOCK_BYTES],
    output: &mut [u8; AES_BLOCK_BYTES],
) {
    let mut state = [0u32; 4];
    for (column, bytes) in state.iter_mut().zip(input.chunks_exact(4)) {
        *column = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    for column in 0..4 {
        state[column] ^= working_key[column];
    }

    for round in 1..rounds {
        let substituted = substitute_shift_rows(&state);
        for column in 0..4 {
            state[column] = mcol(substituted[column]) ^ working_key[round * 4 + column];
        }
    }

    let substituted = substitute_shift_rows(&state);
    for column in 0..4 {
        let value = substituted[column] ^ working_key[rounds * 4 + column];
        output[column * 4..column * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
}

fn decrypt_block(
    working_key: &WorkingKey,
    rounds: usize,
    input: &[u8; AES_BLOCK_BYTES],
    output: &mut [u8; AES_BLOCK_BYTES],
) {
    let mut state = [0u32; 4];
    for (column, bytes) in state.iter_mut().zip(input.chunks_exact(4)) {
        *column = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    for column in 0..4 {
        state[column] ^= working_key[rounds * 4 + column];
    }

    for round in (1..rounds).rev() {
        let substituted = inverse_substitute_shift_rows(&state);
        for column in 0..4 {
            state[column] = inverse_mcol(substituted[column]) ^ working_key[round * 4 + column];
        }
    }

    let substituted = inverse_substitute_shift_rows(&state);
    for column in 0..4 {
        let value = substituted[column] ^ working_key[column];
        output[column * 4..column * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
}

/// Small-footprint AES implementation corresponding to Bouncy Castle's
/// `AesLightEngine`.
///
/// This type packs the AES state into four `u32` words, uses only the 256-byte
/// S-box and inverse S-box, and calculates `Mcol`/`Inv_Mcol` during each round.
/// It never uses the 2 KiB T-tables of Bouncy Castle's regular portable
/// `AesEngine`, and never selects AES-NI.
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
            working_key: [0u32; MAX_WORKING_KEY_WORDS],
            rounds: 0,
            for_encryption: false,
            initialised: false,
        }
    }

    fn transform(&self, input: &[u8; AES_BLOCK_BYTES], output: &mut [u8; AES_BLOCK_BYTES]) {
        if self.for_encryption {
            encrypt_block(&self.working_key, self.rounds, input, output);
        } else {
            decrypt_block(&self.working_key, self.rounds, input, output);
        }
    }
}

impl Default for AesLightEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockCipher for AesLightEngine {
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

impl BlockCipherInit for AesLightEngine {
    type Params<'a> = AesParams;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        let for_encryption = direction == CipherDirection::Encrypt;
        (self.working_key, self.rounds) = generate_working_key(params.key(), for_encryption);
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mix_columns_inverse_round_trips() {
        for value in [0, 1, u32::MAX, 0x0302_0100, 0xA5C3_7E19] {
            assert_eq!(inverse_mcol(mcol(value)), value);
        }
    }

    #[test]
    fn accessors_and_processing_errors() {
        let mut engine = AesLightEngine::new();
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
}
