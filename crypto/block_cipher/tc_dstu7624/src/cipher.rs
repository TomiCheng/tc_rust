//! Kalyna key schedule and round transformations.

use super::tables::{S0, S1, S2, S3, T0, T1, T2, T3};

const MAX_WORDS: usize = 8;
const MAX_ROUND_KEYS: usize = 19;

pub(super) struct Dstu7624Cipher<const BLOCK_WORDS: usize> {
    round_keys: [[u64; BLOCK_WORDS]; MAX_ROUND_KEYS],
    rounds: usize,
}

impl<const BLOCK_WORDS: usize> Dstu7624Cipher<BLOCK_WORDS> {
    pub(super) const fn new() -> Self {
        Self {
            round_keys: [[0; BLOCK_WORDS]; MAX_ROUND_KEYS],
            rounds: 0,
        }
    }

    pub(super) fn set_key(&mut self, key: &[u8]) {
        let key_words = key.len() / 8;
        self.rounds = match key_words {
            2 => 10,
            4 => 14,
            8 => 18,
            _ => unreachable!("engine validates the DSTU 7624 key length"),
        };
        self.round_keys = [[0; BLOCK_WORDS]; MAX_ROUND_KEYS];

        let mut working_key = [0u64; MAX_WORDS];
        for (slot, bytes) in working_key.iter_mut().zip(key.chunks_exact(8)) {
            *slot = u64::from_le_bytes(bytes.try_into().unwrap());
        }

        let temp_key = Self::expand_kt(&working_key, key_words);
        self.expand_even(&working_key, &temp_key, key_words);
        self.expand_odd();
    }

    pub(super) fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
        let mut state = read_words(input, BLOCK_WORDS);
        add_key(&mut state, self.round_key(0), BLOCK_WORDS);

        for round in 1..=self.rounds {
            encryption_round(&mut state, BLOCK_WORDS);
            if round == self.rounds {
                add_key(&mut state, self.round_key(round), BLOCK_WORDS);
            } else {
                xor_key(&mut state, self.round_key(round), BLOCK_WORDS);
            }
        }
        write_words(&state, output, BLOCK_WORDS);
    }

    pub(super) fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
        let mut state = read_words(input, BLOCK_WORDS);
        sub_key(&mut state, self.round_key(self.rounds), BLOCK_WORDS);

        for round in (0..self.rounds).rev() {
            decryption_round(&mut state, BLOCK_WORDS);
            if round == 0 {
                sub_key(&mut state, self.round_key(0), BLOCK_WORDS);
            } else {
                xor_key(&mut state, self.round_key(round), BLOCK_WORDS);
            }
        }
        write_words(&state, output, BLOCK_WORDS);
    }

    fn expand_kt(working_key: &[u64; MAX_WORDS], key_words: usize) -> [u64; MAX_WORDS] {
        let mut state = [0u64; MAX_WORDS];
        let mut k0 = [0u64; MAX_WORDS];
        let mut k1 = [0u64; MAX_WORDS];
        state[0] = (BLOCK_WORDS + key_words + 1) as u64;

        k0[..BLOCK_WORDS].copy_from_slice(&working_key[..BLOCK_WORDS]);
        if BLOCK_WORDS == key_words {
            k1[..BLOCK_WORDS].copy_from_slice(&working_key[..BLOCK_WORDS]);
        } else {
            k1[..BLOCK_WORDS].copy_from_slice(&working_key[BLOCK_WORDS..key_words]);
        }

        add_key(&mut state, &k0, BLOCK_WORDS);
        encryption_round(&mut state, BLOCK_WORDS);
        xor_key(&mut state, &k1, BLOCK_WORDS);
        encryption_round(&mut state, BLOCK_WORDS);
        add_key(&mut state, &k0, BLOCK_WORDS);
        encryption_round(&mut state, BLOCK_WORDS);
        state
    }

    fn expand_even(
        &mut self,
        working_key: &[u64; MAX_WORDS],
        temp_key: &[u64; MAX_WORDS],
        key_words: usize,
    ) {
        let mut initial_data = *working_key;
        let mut round = 0usize;
        let mut tmv = 0x0001_0001_0001_0001u64;

        loop {
            self.generate_even_round(&initial_data[..BLOCK_WORDS], temp_key, tmv, round);
            if round == self.rounds {
                break;
            }

            if key_words != BLOCK_WORDS {
                round += 2;
                tmv <<= 1;
                self.generate_even_round(
                    &initial_data[BLOCK_WORDS..key_words],
                    temp_key,
                    tmv,
                    round,
                );
                if round == self.rounds {
                    break;
                }
            }

            round += 2;
            tmv <<= 1;
            initial_data[..key_words].rotate_left(1);
        }
    }

    fn generate_even_round(
        &mut self,
        data: &[u64],
        temp_key: &[u64; MAX_WORDS],
        tmv: u64,
        round: usize,
    ) {
        let mut state = [0u64; MAX_WORDS];
        let mut temp_round_key = [0u64; MAX_WORDS];
        for word in 0..BLOCK_WORDS {
            temp_round_key[word] = temp_key[word].wrapping_add(tmv);
            state[word] = data[word].wrapping_add(temp_round_key[word]);
        }
        encryption_round(&mut state, BLOCK_WORDS);
        xor_key(&mut state, &temp_round_key, BLOCK_WORDS);
        encryption_round(&mut state, BLOCK_WORDS);
        add_key(&mut state, &temp_round_key, BLOCK_WORDS);
        self.round_key_mut(round)
            .copy_from_slice(&state[..BLOCK_WORDS]);
    }

    fn expand_odd(&mut self) {
        for round in (1..self.rounds).step_by(2) {
            let mut previous = [0u64; MAX_WORDS];
            previous[..BLOCK_WORDS].copy_from_slice(self.round_key(round - 1));
            let mut rotated = [0u64; MAX_WORDS];
            rotate_round_key(&previous, &mut rotated, BLOCK_WORDS);
            self.round_key_mut(round)
                .copy_from_slice(&rotated[..BLOCK_WORDS]);
        }
    }

    fn round_key(&self, round: usize) -> &[u64] {
        &self.round_keys[round]
    }

    fn round_key_mut(&mut self, round: usize) -> &mut [u64] {
        &mut self.round_keys[round]
    }
}

fn read_words(input: &[u8], words: usize) -> [u64; MAX_WORDS] {
    let mut result = [0u64; MAX_WORDS];
    for (index, chunk) in input[..words * 8].chunks_exact(8).enumerate() {
        result[index] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    result
}

fn write_words(state: &[u64; MAX_WORDS], output: &mut [u8], words: usize) {
    for (index, value) in state[..words].iter().enumerate() {
        output[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
}

fn add_key(state: &mut [u64; MAX_WORDS], key: &[u64], words: usize) {
    for index in 0..words {
        state[index] = state[index].wrapping_add(key[index]);
    }
}

fn sub_key(state: &mut [u64; MAX_WORDS], key: &[u64], words: usize) {
    for index in 0..words {
        state[index] = state[index].wrapping_sub(key[index]);
    }
}

fn xor_key(state: &mut [u64; MAX_WORDS], key: &[u64], words: usize) {
    for index in 0..words {
        state[index] ^= key[index];
    }
}

fn encryption_round(state: &mut [u64; MAX_WORDS], words: usize) {
    sub_bytes(state, words, false);
    shift_rows(state, words, false);
    mix_columns(state, words, false);
}

fn decryption_round(state: &mut [u64; MAX_WORDS], words: usize) {
    mix_columns(state, words, true);
    shift_rows(state, words, true);
    sub_bytes(state, words, true);
}

fn sub_bytes(state: &mut [u64; MAX_WORDS], words: usize, inverse: bool) {
    let boxes = if inverse {
        [&T0, &T1, &T2, &T3]
    } else {
        [&S0, &S1, &S2, &S3]
    };
    for value in &mut state[..words] {
        let input = *value;
        let mut output = 0u64;
        for byte in 0..8 {
            let index = ((input >> (byte * 8)) & 0xff) as usize;
            output |= (boxes[byte & 3][index] as u64) << (byte * 8);
        }
        *value = output;
    }
}

fn shift_rows(state: &mut [u64; MAX_WORDS], words: usize, inverse: bool) {
    let input = *state;
    for (column, state_word) in state.iter_mut().take(words).enumerate() {
        let mut output = 0u64;
        for row in 0..8 {
            let shift = row * words / 8;
            let source_column = if inverse {
                (column + shift) % words
            } else {
                (column + words - shift) % words
            };
            let value = (input[source_column] >> (row * 8)) & 0xff;
            output |= value << (row * 8);
        }
        *state_word = output;
    }
}

fn mix_columns(state: &mut [u64; MAX_WORDS], words: usize, inverse: bool) {
    for value in &mut state[..words] {
        *value = if inverse {
            mix_column_inverse(*value)
        } else {
            mix_column(*value)
        };
    }
}

fn mix_column(value: u64) -> u64 {
    let x1 = mul_x(value);
    let mut u = value.rotate_right(8) ^ value;
    u ^= u.rotate_right(16);
    u ^= value.rotate_right(48);
    let v = mul_x2(u ^ value ^ x1);
    u ^ v.rotate_right(32) ^ x1.rotate_right(40) ^ x1.rotate_right(48)
}

fn mix_column_inverse(value: u64) -> u64 {
    let mut u0 = value;
    u0 ^= u0.rotate_right(8);
    u0 ^= u0.rotate_right(32);
    u0 ^= value.rotate_right(48);

    let t = u0 ^ value;
    let c48 = value.rotate_right(48);
    let c56 = value.rotate_right(56);
    let u7 = t ^ c56;
    let mut u6 = t.rotate_right(56);
    u6 ^= mul_x(u7);
    let mut u5 = t.rotate_right(16) ^ value;
    u5 ^= (mul_x(u6) ^ value).rotate_right(40);
    let mut u4 = t ^ c48;
    u4 ^= mul_x(u5);
    let mut u3 = u0.rotate_right(16);
    u3 ^= mul_x(u4);
    let mut u2 = t ^ value.rotate_right(24) ^ c48 ^ c56;
    u2 ^= mul_x(u3);
    let mut u1 = t.rotate_right(32) ^ value ^ c56;
    u1 ^= mul_x(u2);
    u0 ^= mul_x(u1.rotate_right(40));
    u0
}

fn mul_x(value: u64) -> u64 {
    ((value & 0x7f7f_7f7f_7f7f_7f7f) << 1) ^ (((value & 0x8080_8080_8080_8080) >> 7) * 0x1d)
}

fn mul_x2(value: u64) -> u64 {
    ((value & 0x3f3f_3f3f_3f3f_3f3f) << 2)
        ^ (((value & 0x8080_8080_8080_8080) >> 6) * 0x1d)
        ^ (((value & 0x4040_4040_4040_4040) >> 6) * 0x1d)
}

fn rotate_round_key(input: &[u64; MAX_WORDS], output: &mut [u64; MAX_WORDS], words: usize) {
    match words {
        2 => {
            output[0] = (input[0] >> 56) | (input[1] << 8);
            output[1] = (input[1] >> 56) | (input[0] << 8);
        }
        4 => {
            output[0] = (input[1] >> 24) | (input[2] << 40);
            output[1] = (input[2] >> 24) | (input[3] << 40);
            output[2] = (input[3] >> 24) | (input[0] << 40);
            output[3] = (input[0] >> 24) | (input[1] << 40);
        }
        8 => {
            for index in 0..8 {
                output[index] = (input[(index + 2) & 7] >> 24) | (input[(index + 3) & 7] << 40);
            }
        }
        _ => unreachable!("Dstu7624Engine validates block size"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_components_have_working_inverses() {
        for words in [2, 4, 8] {
            let original = core::array::from_fn(|index| {
                0x0123_4567_89ab_cdefu64.rotate_left(index as u32 * 7)
            });

            let mut state = original;
            sub_bytes(&mut state, words, false);
            sub_bytes(&mut state, words, true);
            assert_eq!(&state[..words], &original[..words]);

            let mut state = original;
            shift_rows(&mut state, words, false);
            shift_rows(&mut state, words, true);
            assert_eq!(&state[..words], &original[..words]);
        }

        for value in [0, 1, u64::MAX, 0x0123_4567_89ab_cdef, 0xa55a_c33c_f00f_9669] {
            assert_eq!(mix_column_inverse(mix_column(value)), value);
        }
    }
}
