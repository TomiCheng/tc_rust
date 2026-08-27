//! Portable AES key expansion and block transformations.

use super::{AES_BLOCK_BYTES, RoundKeys};

const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    let mut index = 0;
    while index < 8 {
        product ^= a & 0u8.wrapping_sub(b & 1);
        let high_bit = a >> 7;
        a = (a << 1) ^ (0x1B & 0u8.wrapping_sub(high_bit));
        b >>= 1;
        index += 1;
    }
    product
}

const fn gf_pow(mut value: u8, mut exponent: u8) -> u8 {
    let mut result = 1u8;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, value);
        }
        value = gf_mul(value, value);
        exponent >>= 1;
    }
    result
}

const fn s_box_value(value: u8) -> u8 {
    let inverse = if value == 0 { 0 } else { gf_pow(value, 254) };
    inverse
        ^ inverse.rotate_left(1)
        ^ inverse.rotate_left(2)
        ^ inverse.rotate_left(3)
        ^ inverse.rotate_left(4)
        ^ 0x63
}

const fn build_s_box() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut index = 0;
    while index < 256 {
        table[index] = s_box_value(index as u8);
        index += 1;
    }
    table
}

pub(super) const S_BOX: [u8; 256] = build_s_box();

const fn build_inverse_s_box() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut index = 0;
    while index < 256 {
        table[S_BOX[index] as usize] = index as u8;
        index += 1;
    }
    table
}

pub(super) const INVERSE_S_BOX: [u8; 256] = build_inverse_s_box();

pub(super) fn expand_key(key: &[u8]) -> (RoundKeys, usize) {
    let rounds = match key.len() {
        16 => 10,
        24 => 12,
        32 => 14,
        _ => unreachable!("AesParams validates the key length"),
    };
    let expanded_len = AES_BLOCK_BYTES * (rounds + 1);
    let mut expanded = [0u8; AES_BLOCK_BYTES * 15];
    expanded[..key.len()].copy_from_slice(key);

    let mut generated = key.len();
    let mut rcon = 1u8;
    let mut temp = [0u8; 4];
    while generated < expanded_len {
        temp.copy_from_slice(&expanded[generated - 4..generated]);
        if generated.is_multiple_of(key.len()) {
            temp.rotate_left(1);
            for value in &mut temp {
                *value = s_box_value(*value);
            }
            temp[0] ^= rcon;
            rcon = gf_mul(rcon, 2);
        } else if key.len() == 32 && generated % key.len() == 16 {
            for value in &mut temp {
                *value = s_box_value(*value);
            }
        }

        for value in temp {
            expanded[generated] = expanded[generated - key.len()] ^ value;
            generated += 1;
        }
    }

    let mut round_keys = [[0u8; AES_BLOCK_BYTES]; 15];
    for (round_key, bytes) in round_keys
        .iter_mut()
        .zip(expanded[..expanded_len].chunks_exact(AES_BLOCK_BYTES))
    {
        round_key.copy_from_slice(bytes);
    }
    (round_keys, rounds)
}

#[inline]
fn add_round_key(state: &mut [u8; AES_BLOCK_BYTES], key: &[u8; AES_BLOCK_BYTES]) {
    for index in 0..AES_BLOCK_BYTES {
        state[index] ^= key[index];
    }
}

#[inline]
fn sub_bytes(state: &mut [u8; AES_BLOCK_BYTES]) {
    for value in state {
        *value = S_BOX[*value as usize];
    }
}

#[inline]
fn inverse_sub_bytes(state: &mut [u8; AES_BLOCK_BYTES]) {
    for value in state {
        *value = INVERSE_S_BOX[*value as usize];
    }
}

#[inline]
fn shift_rows(state: &mut [u8; AES_BLOCK_BYTES]) {
    let input = *state;
    for row in 0..4 {
        for column in 0..4 {
            state[row + 4 * column] = input[row + 4 * ((column + row) & 3)];
        }
    }
}

#[inline]
fn inverse_shift_rows(state: &mut [u8; AES_BLOCK_BYTES]) {
    let input = *state;
    for row in 0..4 {
        for column in 0..4 {
            state[row + 4 * column] = input[row + 4 * ((column + 4 - row) & 3)];
        }
    }
}

#[inline]
fn xtime(value: u8) -> u8 {
    (value << 1) ^ (0x1B & 0u8.wrapping_sub(value >> 7))
}

#[inline]
fn mix_columns(state: &mut [u8; AES_BLOCK_BYTES]) {
    for column in state.chunks_exact_mut(4) {
        let a = [column[0], column[1], column[2], column[3]];
        let all = a[0] ^ a[1] ^ a[2] ^ a[3];
        column[0] ^= all ^ xtime(a[0] ^ a[1]);
        column[1] ^= all ^ xtime(a[1] ^ a[2]);
        column[2] ^= all ^ xtime(a[2] ^ a[3]);
        column[3] ^= all ^ xtime(a[3] ^ a[0]);
    }
}

#[inline]
fn inverse_mix_columns(state: &mut [u8; AES_BLOCK_BYTES]) {
    for column in state.chunks_exact_mut(4) {
        let a = [column[0], column[1], column[2], column[3]];
        let u = xtime(xtime(a[0] ^ a[2]));
        let v = xtime(xtime(a[1] ^ a[3]));
        column[0] ^= u;
        column[1] ^= v;
        column[2] ^= u;
        column[3] ^= v;
    }
    mix_columns(state);
}

pub(super) fn encrypt_block(
    round_keys: &RoundKeys,
    rounds: usize,
    input: &[u8; AES_BLOCK_BYTES],
    output: &mut [u8; AES_BLOCK_BYTES],
) {
    let mut state = *input;
    add_round_key(&mut state, &round_keys[0]);
    for round_key in &round_keys[1..rounds] {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, round_key);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[rounds]);
    *output = state;
}

pub(super) fn decrypt_block(
    round_keys: &RoundKeys,
    rounds: usize,
    input: &[u8; AES_BLOCK_BYTES],
    output: &mut [u8; AES_BLOCK_BYTES],
) {
    let mut state = *input;
    add_round_key(&mut state, &round_keys[rounds]);
    for round_key in round_keys[1..rounds].iter().rev() {
        inverse_shift_rows(&mut state);
        inverse_sub_bytes(&mut state);
        add_round_key(&mut state, round_key);
        inverse_mix_columns(&mut state);
    }
    inverse_shift_rows(&mut state);
    inverse_sub_bytes(&mut state);
    add_round_key(&mut state, &round_keys[0]);
    *output = state;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_s_boxes_have_standard_endpoints() {
        assert_eq!(&S_BOX[..4], &[0x63, 0x7C, 0x77, 0x7B]);
        assert_eq!(&S_BOX[252..], &[0xB0, 0x54, 0xBB, 0x16]);
        for value in 0..=255u8 {
            assert_eq!(INVERSE_S_BOX[S_BOX[value as usize] as usize], value);
        }
    }
}
