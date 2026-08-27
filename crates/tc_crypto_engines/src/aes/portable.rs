//! Portable AES key expansion and block transformations using Bouncy Castle's
//! single forward/inverse T-table strategy.

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

static T0: [u32; 256] = build_t0();
static INVERSE_T0: [u32; 256] = build_inverse_t0();

#[inline]
fn round_key_word(round_keys: &RoundKeys, round: usize, column: usize) -> u32 {
    let offset = column * 4;
    u32::from_le_bytes(round_keys[round][offset..offset + 4].try_into().unwrap())
}

#[inline]
fn set_round_key_word(round_keys: &mut RoundKeys, round: usize, column: usize, value: u32) {
    let offset = column * 4;
    round_keys[round][offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

const fn inverse_mix_word(value: u32) -> u32 {
    let bytes = value.to_le_bytes();
    u32::from_le_bytes([
        gf_mul(bytes[0], 14) ^ gf_mul(bytes[1], 11) ^ gf_mul(bytes[2], 13) ^ gf_mul(bytes[3], 9),
        gf_mul(bytes[0], 9) ^ gf_mul(bytes[1], 14) ^ gf_mul(bytes[2], 11) ^ gf_mul(bytes[3], 13),
        gf_mul(bytes[0], 13) ^ gf_mul(bytes[1], 9) ^ gf_mul(bytes[2], 14) ^ gf_mul(bytes[3], 11),
        gf_mul(bytes[0], 11) ^ gf_mul(bytes[1], 13) ^ gf_mul(bytes[2], 9) ^ gf_mul(bytes[3], 14),
    ])
}

pub(super) fn prepare_decryption_keys(round_keys: &mut RoundKeys, rounds: usize) {
    for round in 1..rounds {
        for column in 0..4 {
            let value = inverse_mix_word(round_key_word(round_keys, round, column));
            set_round_key_word(round_keys, round, column, value);
        }
    }
}

#[inline]
fn load_state(input: &[u8; AES_BLOCK_BYTES]) -> [u32; 4] {
    core::array::from_fn(|column| {
        let offset = column * 4;
        u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap())
    })
}

#[inline]
fn encrypt_round(state: &[u32; 4]) -> [u32; 4] {
    let t = |word: usize, shift: u32, rotate: u32| {
        T0[((state[word] >> shift) & 0xFF) as usize].rotate_right(rotate)
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
        INVERSE_T0[((state[word] >> shift) & 0xFF) as usize].rotate_right(rotate)
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
fn final_decrypt_round(state: &[u32; 4]) -> [u32; 4] {
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

pub(super) fn encrypt_block(
    round_keys: &RoundKeys,
    rounds: usize,
    input: &[u8; AES_BLOCK_BYTES],
    output: &mut [u8; AES_BLOCK_BYTES],
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
        output[column * 4..column * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
}

pub(super) fn decrypt_block(
    round_keys: &RoundKeys,
    rounds: usize,
    input: &[u8; AES_BLOCK_BYTES],
    output: &mut [u8; AES_BLOCK_BYTES],
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
        output[column * 4..column * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
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

    #[test]
    fn generated_t_tables_match_bouncy_castle_endpoints() {
        assert_eq!(T0[0], 0xA563_63C6);
        assert_eq!(INVERSE_T0[0], 0x50A7_F451);
        assert_eq!(T0.len() * core::mem::size_of::<u32>() * 2, 2048);
    }
}
