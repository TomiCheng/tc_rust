//! Generalized Rijndael engine and round transforms.

use core::fmt;

use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyParams,
};
use tc_zeroize::Zeroize;

use crate::tables::{INV_SHIFTS, RCON, S, SHIFTS, SI};
use crate::{ALGO_NAME, KEY_BYTES};

const MAX_ROUND_KEYS: usize = 15;

/// Rijndael with a compile-time block width and a runtime-selected key width.
///
/// `BLOCK_COLUMNS` must be in `4..=8`, selecting a 128-, 160-, 192-, 224-, or
/// 256-bit block. All five standard Rijndael key lengths are accepted by every
/// variant.
///
/// Variable time: substitutions use secret-dependent S-box lookups, and
/// field multiplication branches on secret data. Use only where cache-timing
/// leakage is outside the threat model; this crate has no constant-time alternative.
///
/// Stored round keys are wiped on replacement and drop. This does not wipe
/// caller buffers or guarantee erasure of every register or stack copy.
///
/// # Example
///
/// ```
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
/// use tc_rijndael_v2::Rijndael256Engine;
///
/// let key = [0x42; 20];
/// let plaintext = [0x11; 32];
/// let mut engine = Rijndael256Engine::new();
/// engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
/// let mut encrypted = [0; 32];
/// engine.process_block(&plaintext, &mut encrypted)?;
/// engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
/// let mut recovered = [0; 32];
/// engine.process_block(&encrypted, &mut recovered)?;
/// assert_eq!(recovered, plaintext);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
///
/// Unsupported block widths are rejected at compile time:
///
/// ```compile_fail
/// const INVALID: tc_rijndael_v2::RijndaelEngine<3> = tc_rijndael_v2::RijndaelEngine::new();
/// ```
pub struct RijndaelEngine<const BLOCK_COLUMNS: usize> {
    round_keys: [[u32; BLOCK_COLUMNS]; MAX_ROUND_KEYS],
    rounds: usize,
    for_encryption: bool,
    initialised: bool,
}

impl<const BLOCK_COLUMNS: usize> RijndaelEngine<BLOCK_COLUMNS> {
    const VALID_BLOCK_COLUMNS: () = assert!(
        valid_block_columns(BLOCK_COLUMNS),
        "Rijndael BLOCK_COLUMNS must be in 4..=8"
    );

    /// Creates an uninitialised engine for the selected block width. Constant time.
    pub const fn new() -> Self {
        let () = Self::VALID_BLOCK_COLUMNS;
        Self {
            round_keys: [[0; BLOCK_COLUMNS]; MAX_ROUND_KEYS],
            rounds: 0,
            for_encryption: false,
            initialised: false,
        }
    }

    const fn block_bytes() -> usize {
        BLOCK_COLUMNS * 4
    }

    const fn row_bits() -> u32 {
        (BLOCK_COLUMNS * 8) as u32
    }

    const fn row_mask() -> u64 {
        if BLOCK_COLUMNS == 8 {
            u64::MAX
        } else {
            (1u64 << Self::row_bits()) - 1
        }
    }

    fn unpack(input: &[u8]) -> [u64; 4] {
        let mut state = [0u64; 4];
        let mut index = 0;
        for shift in (0..Self::row_bits()).step_by(8) {
            for row in &mut state {
                *row |= u64::from(input[index]) << shift;
                index += 1;
            }
        }
        state
    }

    fn pack(state: &[u64; 4], output: &mut [u8]) {
        let mut index = 0;
        for shift in (0..Self::row_bits()).step_by(8) {
            for row in state {
                output[index] = (row >> shift) as u8;
                index += 1;
            }
        }
    }

    fn shift(row: u64, shift: u32) -> u64 {
        ((row >> shift) | (row << (Self::row_bits() - shift))) & Self::row_mask()
    }

    fn shift_rows(state: &mut [u64; 4], shifts: &[u32; 4]) {
        state[1] = Self::shift(state[1], shifts[1]);
        state[2] = Self::shift(state[2], shifts[2]);
        state[3] = Self::shift(state[3], shifts[3]);
    }

    fn substitute(state: &mut [u64; 4], s_box: &[u8; 256]) {
        for row in state {
            let mut result = 0u64;
            for shift in (0..Self::row_bits()).step_by(8) {
                result |= u64::from(s_box[(((*row) >> shift) & 0xff) as usize]) << shift;
            }
            *row = result;
        }
    }

    fn mix_columns(state: &mut [u64; 4]) {
        let mut result = [0u64; 4];
        for shift in (0..Self::row_bits()).step_by(8) {
            let bytes = [
                ((state[0] >> shift) & 0xff) as u8,
                ((state[1] >> shift) & 0xff) as u8,
                ((state[2] >> shift) & 0xff) as u8,
                ((state[3] >> shift) & 0xff) as u8,
            ];
            for (row, output) in result.iter_mut().enumerate() {
                let value = gf_mul(bytes[row], 2)
                    ^ gf_mul(bytes[(row + 1) % 4], 3)
                    ^ bytes[(row + 2) % 4]
                    ^ bytes[(row + 3) % 4];
                *output |= u64::from(value) << shift;
            }
        }
        *state = result;
    }

    fn inverse_mix_columns(state: &mut [u64; 4]) {
        let mut result = [0u64; 4];
        for shift in (0..Self::row_bits()).step_by(8) {
            let bytes = [
                ((state[0] >> shift) & 0xff) as u8,
                ((state[1] >> shift) & 0xff) as u8,
                ((state[2] >> shift) & 0xff) as u8,
                ((state[3] >> shift) & 0xff) as u8,
            ];
            for (row, output) in result.iter_mut().enumerate() {
                let value = gf_mul(bytes[row], 0x0e)
                    ^ gf_mul(bytes[(row + 1) % 4], 0x0b)
                    ^ gf_mul(bytes[(row + 2) % 4], 0x0d)
                    ^ gf_mul(bytes[(row + 3) % 4], 0x09);
                *output |= u64::from(value) << shift;
            }
        }
        *state = result;
    }

    fn encrypt(&self, state: &mut [u64; 4]) {
        add_round_key(state, &self.round_keys[0]);
        for round in 1..self.rounds {
            Self::substitute(state, &S);
            Self::shift_rows(state, &SHIFTS[BLOCK_COLUMNS - 4]);
            Self::mix_columns(state);
            add_round_key(state, &self.round_keys[round]);
        }
        Self::substitute(state, &S);
        Self::shift_rows(state, &SHIFTS[BLOCK_COLUMNS - 4]);
        add_round_key(state, &self.round_keys[self.rounds]);
    }

    fn decrypt(&self, state: &mut [u64; 4]) {
        add_round_key(state, &self.round_keys[self.rounds]);
        Self::substitute(state, &SI);
        Self::shift_rows(state, &INV_SHIFTS[BLOCK_COLUMNS - 4]);
        for round in (1..self.rounds).rev() {
            add_round_key(state, &self.round_keys[round]);
            Self::inverse_mix_columns(state);
            Self::substitute(state, &SI);
            Self::shift_rows(state, &INV_SHIFTS[BLOCK_COLUMNS - 4]);
        }
        add_round_key(state, &self.round_keys[0]);
    }
}

impl<const BLOCK_COLUMNS: usize> Default for RijndaelEngine<BLOCK_COLUMNS> {
    /// Creates an uninitialised engine. Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl<const BLOCK_COLUMNS: usize> fmt::Display for RijndaelEngine<BLOCK_COLUMNS> {
    /// Writes the algorithm name without inspecting key material.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ALGO_NAME)
    }
}

impl<const BLOCK_COLUMNS: usize> Drop for RijndaelEngine<BLOCK_COLUMNS> {
    fn drop(&mut self) {
        self.round_keys.zeroize();
    }
}

impl<const BLOCK_COLUMNS: usize> BlockCipher for RijndaelEngine<BLOCK_COLUMNS> {
    type Error = BlockError;

    /// Returns the selected block length in bytes. Constant time.
    fn block_size(&self) -> usize {
        Self::block_bytes()
    }

    /// Processes the first block and returns its length, preserving the output tail.
    ///
    /// Returns `NotInitialised` or `BufferTooShort` without touching output.
    /// Variable time: S-box indices and field-multiplication branches depend on secrets.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, BlockError> {
        if !self.initialised {
            return Err(BlockError::NotInitialised);
        }

        let block_bytes = Self::block_bytes();
        if input.len() < block_bytes || output.len() < block_bytes {
            return Err(BlockError::BufferTooShort);
        }

        let mut state = Self::unpack(&input[..block_bytes]);
        if self.for_encryption {
            self.encrypt(&mut state);
        } else {
            self.decrypt(&mut state);
        }
        Self::pack(&state, &mut output[..block_bytes]);
        Ok(block_bytes)
    }
}

impl<P: KeyParams + ?Sized, const BLOCK_COLUMNS: usize> BlockCipherInit<P>
    for RijndaelEngine<BLOCK_COLUMNS>
{
    type Error = InitError;

    /// Installs a 16-, 20-, 24-, 28- or 32-byte key for the selected direction.
    ///
    /// Invalid lengths preserve the previous key, direction and initialization state.
    /// Variable time: key expansion indexes S-boxes with secret data.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !KEY_BYTES.contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        self.round_keys.zeroize();
        self.rounds = expand_key(key, &mut self.round_keys);
        self.for_encryption = direction == CipherDirection::Encrypt;
        self.initialised = true;
        Ok(())
    }
}

fn expand_key<const BLOCK_COLUMNS: usize>(
    key: &[u8],
    round_keys: &mut [[u32; BLOCK_COLUMNS]; MAX_ROUND_KEYS],
) -> usize {
    round_keys.fill([0; BLOCK_COLUMNS]);
    let key_columns = key.len() / 4;
    let rounds = BLOCK_COLUMNS.max(key_columns) + 6;
    let total_columns = (rounds + 1) * BLOCK_COLUMNS;

    let mut temporary_key = [[0u8; 8]; 4];
    for (column, bytes) in key.chunks_exact(4).enumerate() {
        for row in 0..4 {
            temporary_key[row][column] = bytes[row];
        }
    }

    let mut generated = 0;
    copy_key_columns(
        &temporary_key,
        key_columns,
        round_keys,
        total_columns,
        &mut generated,
    );

    let mut rcon_index = 0;
    while generated < total_columns {
        for row in 0..4 {
            temporary_key[row][0] ^= S[temporary_key[(row + 1) % 4][key_columns - 1] as usize];
        }
        temporary_key[0][0] ^= RCON[rcon_index];
        rcon_index += 1;

        if key_columns <= 6 {
            for column in 1..key_columns {
                for row in &mut temporary_key {
                    row[column] ^= row[column - 1];
                }
            }
        } else {
            for column in 1..4 {
                for row in &mut temporary_key {
                    row[column] ^= row[column - 1];
                }
            }
            for row in &mut temporary_key {
                row[4] ^= S[row[3] as usize];
            }
            for column in 5..key_columns {
                for row in &mut temporary_key {
                    row[column] ^= row[column - 1];
                }
            }
        }

        copy_key_columns(
            &temporary_key,
            key_columns,
            round_keys,
            total_columns,
            &mut generated,
        );
    }
    temporary_key.zeroize();
    rounds
}

fn copy_key_columns<const BLOCK_COLUMNS: usize>(
    temporary_key: &[[u8; 8]; 4],
    key_columns: usize,
    round_keys: &mut [[u32; BLOCK_COLUMNS]; MAX_ROUND_KEYS],
    total_columns: usize,
    generated: &mut usize,
) {
    let mut column = 0;
    while column < key_columns && *generated < total_columns {
        round_keys[*generated / BLOCK_COLUMNS][*generated % BLOCK_COLUMNS] = u32::from_le_bytes([
            temporary_key[0][column],
            temporary_key[1][column],
            temporary_key[2][column],
            temporary_key[3][column],
        ]);
        column += 1;
        *generated += 1;
    }
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if right & 1 != 0 {
            result ^= left;
        }
        let high_bit = left & 0x80;
        left <<= 1;
        if high_bit != 0 {
            left ^= 0x1b;
        }
        right >>= 1;
    }
    result
}

fn add_round_key<const BLOCK_COLUMNS: usize>(
    state: &mut [u64; 4],
    round_key: &[u32; BLOCK_COLUMNS],
) {
    for (column, word) in round_key.iter().enumerate() {
        let bytes = word.to_le_bytes();
        let shift = column * 8;
        for row in 0..4 {
            state[row] ^= u64::from(bytes[row]) << shift;
        }
    }
}

/// Checks the public block-width parameter. Constant time with respect to key material.
pub(crate) const fn valid_block_columns(columns: usize) -> bool {
    columns >= 4 && columns <= 8
}

/// Rijndael engine with a 128-bit block.
pub type Rijndael128Engine = RijndaelEngine<4>;
/// Rijndael engine with a 160-bit block.
pub type Rijndael160Engine = RijndaelEngine<5>;
/// Rijndael engine with a 192-bit block.
pub type Rijndael192Engine = RijndaelEngine<6>;
/// Rijndael engine with a 224-bit block.
pub type Rijndael224Engine = RijndaelEngine<7>;
/// Rijndael engine with a 256-bit block.
pub type Rijndael256Engine = RijndaelEngine<8>;
