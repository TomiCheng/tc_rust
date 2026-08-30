//! Generalized Rijndael engine, exact-size key schedule, and round transforms.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use super::tables::{ALOG, LOG, RCON, S, SHIFTS0, SHIFTS1, SI};
use super::{
    BlockCipherError, RijndaelConfig, RijndaelParams, ValidRijndaelConfig,
};

macro_rules! impl_configuration {
    ($block:literal, $key:literal, $round_keys:literal) => {
        impl ValidRijndaelConfig<$block> for RijndaelConfig<$block, $key> {
            type Schedule = [[u32; $block]; $round_keys];

            fn new_schedule() -> Self::Schedule {
                [[0_u32; $block]; $round_keys]
            }

            fn schedule(schedule: &Self::Schedule) -> &[[u32; $block]] {
                schedule
            }

            fn schedule_mut(schedule: &mut Self::Schedule) -> &mut [[u32; $block]] {
                schedule
            }
        }
    };
}

impl_configuration!(4, 4, 11);
impl_configuration!(4, 5, 12);
impl_configuration!(4, 6, 13);
impl_configuration!(4, 7, 14);
impl_configuration!(4, 8, 15);
impl_configuration!(5, 4, 12);
impl_configuration!(5, 5, 12);
impl_configuration!(5, 6, 13);
impl_configuration!(5, 7, 14);
impl_configuration!(5, 8, 15);
impl_configuration!(6, 4, 13);
impl_configuration!(6, 5, 13);
impl_configuration!(6, 6, 13);
impl_configuration!(6, 7, 14);
impl_configuration!(6, 8, 15);
impl_configuration!(7, 4, 14);
impl_configuration!(7, 5, 14);
impl_configuration!(7, 6, 14);
impl_configuration!(7, 7, 14);
impl_configuration!(7, 8, 15);
impl_configuration!(8, 4, 15);
impl_configuration!(8, 5, 15);
impl_configuration!(8, 6, 15);
impl_configuration!(8, 7, 15);
impl_configuration!(8, 8, 15);

/// Generalized Rijndael with compile-time block and key widths.
///
/// Both const parameters count 32-bit columns and must be in `4..=8`. All 25
/// standard combinations are implemented. The round-key table is selected by
/// an internal configuration mapping, so it contains exactly
/// `max(BLOCK_COLUMNS, KEY_COLUMNS) + 7` round keys.
pub struct RijndaelEngine<const BLOCK_COLUMNS: usize, const KEY_COLUMNS: usize>
where
    RijndaelConfig<BLOCK_COLUMNS, KEY_COLUMNS>: ValidRijndaelConfig<BLOCK_COLUMNS>,
{
    working_key: <RijndaelConfig<BLOCK_COLUMNS, KEY_COLUMNS> as ValidRijndaelConfig<
        BLOCK_COLUMNS,
    >>::Schedule,
    initialised: bool,
    for_encryption: bool,
}

impl<const BLOCK_COLUMNS: usize, const KEY_COLUMNS: usize>
    RijndaelEngine<BLOCK_COLUMNS, KEY_COLUMNS>
where
    RijndaelConfig<BLOCK_COLUMNS, KEY_COLUMNS>: ValidRijndaelConfig<BLOCK_COLUMNS>,
{
    /// Creates an uninitialized engine for the selected block/key combination.
    pub fn new() -> Self {
        Self {
            working_key: <RijndaelConfig<BLOCK_COLUMNS, KEY_COLUMNS> as ValidRijndaelConfig<
                BLOCK_COLUMNS,
            >>::new_schedule(),
            initialised: false,
            for_encryption: false,
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
            (1_u64 << Self::row_bits()) - 1
        }
    }

    fn unpack(input: &[u8]) -> [u64; 4] {
        let mut state = [0_u64; 4];
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

    fn apply_s(row: u64, sbox: &[u8; 256]) -> u64 {
        let mut result = 0_u64;
        for shift in (0..Self::row_bits()).step_by(8) {
            result |= u64::from(sbox[((row >> shift) & 0xff) as usize]) << shift;
        }
        result
    }

    fn substitution(state: &mut [u64; 4], sbox: &[u8; 256]) {
        for row in state {
            *row = Self::apply_s(*row, sbox);
        }
    }

    fn mix_column(state: &mut [u64; 4]) {
        let mut result = [0_u64; 4];
        for shift in (0..Self::row_bits()).step_by(8) {
            let bytes = [
                ((state[0] >> shift) & 0xff) as i32,
                ((state[1] >> shift) & 0xff) as i32,
                ((state[2] >> shift) & 0xff) as i32,
                ((state[3] >> shift) & 0xff) as i32,
            ];
            for (row, output) in result.iter_mut().enumerate() {
                let value = mul2(bytes[row])
                    ^ mul3(bytes[(row + 1) % 4])
                    ^ bytes[(row + 2) % 4]
                    ^ bytes[(row + 3) % 4];
                *output |= u64::from((value & 0xff) as u8) << shift;
            }
        }
        *state = result;
    }

    fn inv_mix_column(state: &mut [u64; 4]) {
        let mut result = [0_u64; 4];
        for shift in (0..Self::row_bits()).step_by(8) {
            let bytes = [
                pre_log(((state[0] >> shift) & 0xff) as i32),
                pre_log(((state[1] >> shift) & 0xff) as i32),
                pre_log(((state[2] >> shift) & 0xff) as i32),
                pre_log(((state[3] >> shift) & 0xff) as i32),
            ];
            for (row, output) in result.iter_mut().enumerate() {
                let value = mul_e(bytes[row])
                    ^ mul_b(bytes[(row + 1) % 4])
                    ^ mul_d(bytes[(row + 2) % 4])
                    ^ mul_9(bytes[(row + 3) % 4]);
                *output |= u64::from((value & 0xff) as u8) << shift;
            }
        }
        *state = result;
    }

    fn encrypt_block(state: &mut [u64; 4], round_keys: &[[u32; BLOCK_COLUMNS]]) {
        let rounds = round_keys.len() - 1;
        key_addition(state, &round_keys[0]);
        for round_key in round_keys.iter().take(rounds).skip(1) {
            Self::substitution(state, &S);
            Self::shift_rows(state, &SHIFTS0[BLOCK_COLUMNS - 4]);
            Self::mix_column(state);
            key_addition(state, round_key);
        }
        Self::substitution(state, &S);
        Self::shift_rows(state, &SHIFTS0[BLOCK_COLUMNS - 4]);
        key_addition(state, &round_keys[rounds]);
    }

    fn decrypt_block(state: &mut [u64; 4], round_keys: &[[u32; BLOCK_COLUMNS]]) {
        let rounds = round_keys.len() - 1;
        key_addition(state, &round_keys[rounds]);
        Self::substitution(state, &SI);
        Self::shift_rows(state, &SHIFTS1[BLOCK_COLUMNS - 4]);
        for round in (1..rounds).rev() {
            key_addition(state, &round_keys[round]);
            Self::inv_mix_column(state);
            Self::substitution(state, &SI);
            Self::shift_rows(state, &SHIFTS1[BLOCK_COLUMNS - 4]);
        }
        key_addition(state, &round_keys[0]);
    }

    fn generate_working_key(
        params: &RijndaelParams<KEY_COLUMNS>,
    ) -> <RijndaelConfig<BLOCK_COLUMNS, KEY_COLUMNS> as ValidRijndaelConfig<
        BLOCK_COLUMNS,
    >>::Schedule {
        let mut schedule = <RijndaelConfig<BLOCK_COLUMNS, KEY_COLUMNS> as ValidRijndaelConfig<
            BLOCK_COLUMNS,
        >>::new_schedule();
        let round_keys = <RijndaelConfig<BLOCK_COLUMNS, KEY_COLUMNS> as ValidRijndaelConfig<
            BLOCK_COLUMNS,
        >>::schedule_mut(&mut schedule);
        let total_columns = round_keys.len() * BLOCK_COLUMNS;

        let mut temporary_key = [[0_u8; KEY_COLUMNS]; 4];
        for (column, bytes) in params.key_columns().iter().enumerate() {
            for row in 0..4 {
                temporary_key[row][column] = bytes[row];
            }
        }

        let mut generated = 0_usize;
        let copy_temporary = |temporary_key: &[[u8; KEY_COLUMNS]; 4],
                              round_keys: &mut [[u32; BLOCK_COLUMNS]],
                              generated: &mut usize| {
            let mut column = 0;
            while column < KEY_COLUMNS && *generated < total_columns {
                round_keys[*generated / BLOCK_COLUMNS][*generated % BLOCK_COLUMNS] =
                    u32::from_le_bytes([
                        temporary_key[0][column],
                        temporary_key[1][column],
                        temporary_key[2][column],
                        temporary_key[3][column],
                    ]);
                column += 1;
                *generated += 1;
            }
        };

        copy_temporary(&temporary_key, round_keys, &mut generated);

        let mut rcon_pointer = 0;
        while generated < total_columns {
            for row in 0..4 {
                temporary_key[row][0] ^=
                    S[temporary_key[(row + 1) % 4][KEY_COLUMNS - 1] as usize];
            }
            temporary_key[0][0] ^= RCON[rcon_pointer];
            rcon_pointer += 1;

            if KEY_COLUMNS <= 6 {
                for column in 1..KEY_COLUMNS {
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
                for column in 5..KEY_COLUMNS {
                    for row in &mut temporary_key {
                        row[column] ^= row[column - 1];
                    }
                }
            }

            copy_temporary(&temporary_key, round_keys, &mut generated);
        }
        schedule
    }
}

impl<const BLOCK_COLUMNS: usize, const KEY_COLUMNS: usize> Default
    for RijndaelEngine<BLOCK_COLUMNS, KEY_COLUMNS>
where
    RijndaelConfig<BLOCK_COLUMNS, KEY_COLUMNS>: ValidRijndaelConfig<BLOCK_COLUMNS>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const BLOCK_COLUMNS: usize, const KEY_COLUMNS: usize> BlockCipher
    for RijndaelEngine<BLOCK_COLUMNS, KEY_COLUMNS>
where
    RijndaelConfig<BLOCK_COLUMNS, KEY_COLUMNS>: ValidRijndaelConfig<BLOCK_COLUMNS>,
{
    type Error = BlockCipherError;

    fn algorithm_name(&self) -> &str {
        "Rijndael"
    }

    fn block_size(&self) -> usize {
        Self::block_bytes()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(BlockCipherError::NotInitialised);
        }
        let bytes = Self::block_bytes();
        if input.len() < bytes || output.len() < bytes {
            return Err(BlockCipherError::BufferTooShort);
        }

        let round_keys = <RijndaelConfig<BLOCK_COLUMNS, KEY_COLUMNS> as ValidRijndaelConfig<
            BLOCK_COLUMNS,
        >>::schedule(&self.working_key);
        let mut state = Self::unpack(input);
        if self.for_encryption {
            Self::encrypt_block(&mut state, round_keys);
        } else {
            Self::decrypt_block(&mut state, round_keys);
        }
        Self::pack(&state, output);
        Ok(bytes)
    }
}

impl<const BLOCK_COLUMNS: usize, const KEY_COLUMNS: usize> BlockCipherInit
    for RijndaelEngine<BLOCK_COLUMNS, KEY_COLUMNS>
where
    RijndaelConfig<BLOCK_COLUMNS, KEY_COLUMNS>: ValidRijndaelConfig<BLOCK_COLUMNS>,
{
    type Params<'a> = RijndaelParams<KEY_COLUMNS>;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.working_key = Self::generate_working_key(params);
        self.initialised = true;
        self.for_encryption = direction == CipherDirection::Encrypt;
        Ok(())
    }
}

fn pre_log(byte: i32) -> i32 {
    if byte != 0 {
        i32::from(LOG[byte as usize])
    } else {
        -1
    }
}

fn mul2(byte: i32) -> i32 {
    if byte != 0 {
        i32::from(ALOG[25 + LOG[byte as usize] as usize])
    } else {
        0
    }
}

fn mul3(byte: i32) -> i32 {
    if byte != 0 {
        i32::from(ALOG[1 + LOG[byte as usize] as usize])
    } else {
        0
    }
}

fn alog_at(offset: usize, log: i32) -> i32 {
    if log >= 0 {
        i32::from(ALOG[offset + log as usize])
    } else {
        0
    }
}

fn mul_9(log: i32) -> i32 {
    alog_at(199, log)
}

fn mul_b(log: i32) -> i32 {
    alog_at(104, log)
}

fn mul_d(log: i32) -> i32 {
    alog_at(238, log)
}

fn mul_e(log: i32) -> i32 {
    alog_at(223, log)
}

fn key_addition<const BLOCK_COLUMNS: usize>(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_and_pre_init_errors() {
        let mut engine = RijndaelEngine::<4, 4>::new();
        assert_eq!(engine.algorithm_name(), "Rijndael");
        assert_eq!(engine.block_size(), 16);
        assert_eq!(
            engine.process_block(&[0_u8; 16], &mut [0_u8; 16]),
            Err(BlockCipherError::NotInitialised)
        );
    }

    #[test]
    fn block_size_is_selected_by_the_type() {
        assert_eq!(RijndaelEngine::<4, 8>::new().block_size(), 16);
        assert_eq!(RijndaelEngine::<8, 4>::new().block_size(), 32);
    }

    #[test]
    fn schedule_storage_matches_each_selected_combination() {
        let engine = RijndaelEngine::<4, 4>::new();
        let schedule = <RijndaelConfig<4, 4> as ValidRijndaelConfig<4>>::schedule(
            &engine.working_key,
        );
        assert_eq!(core::mem::size_of_val(schedule), 11 * 4 * 4);

        let engine = RijndaelEngine::<4, 8>::new();
        let schedule = <RijndaelConfig<4, 8> as ValidRijndaelConfig<4>>::schedule(
            &engine.working_key,
        );
        assert_eq!(core::mem::size_of_val(schedule), 15 * 4 * 4);

        let engine = RijndaelEngine::<8, 4>::new();
        let schedule = <RijndaelConfig<8, 4> as ValidRijndaelConfig<8>>::schedule(
            &engine.working_key,
        );
        assert_eq!(core::mem::size_of_val(schedule), 15 * 8 * 4);
    }
}
