//! Portable AES key expansion and block transformations, following Bouncy
//! Castle's single forward/inverse T-table strategy.

use crate::BLOCK_BYTES;

/// Round keys for the longest schedule (AES-256 uses fourteen rounds plus the
/// initial whitening key).
pub(crate) const MAX_ROUND_KEYS: usize = 15;
/// The expanded key, one block per round.
pub(crate) type RoundKeys = [[u8; BLOCK_BYTES]; MAX_ROUND_KEYS];

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

pub(crate) const S_BOX: [u8; 256] = build_s_box();

const fn build_inverse_s_box() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut index = 0;
    while index < 256 {
        table[S_BOX[index] as usize] = index as u8;
        index += 1;
    }
    table
}

pub(crate) const INVERSE_S_BOX: [u8; 256] = build_inverse_s_box();

/// Rounds for a key length, or `None` if AES defines none.
///
/// Both engines validate through this, so the key-length rule lives in one
/// place and neither block path needs a panicking fallback.
pub(crate) const fn rounds_for(key_len: usize) -> Option<usize> {
    match key_len {
        16 => Some(10),
        24 => Some(12),
        32 => Some(14),
        _ => None,
    }
}

/// Expands `key` into the round keys; `rounds` comes from [`rounds_for`].
pub(crate) fn expand_key(key: &[u8], rounds: usize) -> RoundKeys {
    let expanded_len = BLOCK_BYTES * (rounds + 1);
    let mut expanded = [0u8; BLOCK_BYTES * MAX_ROUND_KEYS];
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

    let mut round_keys = [[0u8; BLOCK_BYTES]; MAX_ROUND_KEYS];
    for (round_key, bytes) in round_keys
        .iter_mut()
        .zip(expanded[..expanded_len].chunks_exact(BLOCK_BYTES))
    {
        round_key.copy_from_slice(bytes);
    }
    round_keys
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

pub(crate) fn prepare_decryption_keys(round_keys: &mut RoundKeys, rounds: usize) {
    for round in 1..rounds {
        for column in 0..4 {
            let value = inverse_mix_word(round_key_word(round_keys, round, column));
            set_round_key_word(round_keys, round, column, value);
        }
    }
}

#[inline]
fn load_state(input: &[u8; BLOCK_BYTES]) -> [u32; 4] {
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

pub(crate) fn encrypt_block(
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
        output[column * 4..column * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
}

pub(crate) fn decrypt_block(
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
        output[column * 4..column * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_s_boxes_have_standard_endpoints() {
        // S-box 是 const fn 由 GF(2^8) 反元素算出來的,不是抄表。
        assert_eq!(&S_BOX[..4], &[0x63, 0x7c, 0x77, 0x7b]);
        assert_eq!(&S_BOX[252..], &[0xb0, 0x54, 0xbb, 0x16]);
        for value in 0..=u8::MAX {
            assert_eq!(INVERSE_S_BOX[S_BOX[usize::from(value)] as usize], value);
        }
    }

    #[test]
    fn generated_t_tables_match_bouncy_castle_endpoints() {
        assert_eq!(T0[0], 0xa563_63c6);
        assert_eq!(INVERSE_T0[0], 0x50a7_f451);
    }

    #[test]
    fn every_key_length_round_trips() {
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        for key_len in [16, 24, 32] {
            let key = [0x5a_u8; 32];
            let rounds = rounds_for(key_len).unwrap();
            let round_keys = expand_key(&key[..key_len], rounds);

            let mut ciphertext = [0_u8; BLOCK_BYTES];
            encrypt_block(&round_keys, rounds, &plaintext, &mut ciphertext);

            let mut decryption_keys = round_keys;
            prepare_decryption_keys(&mut decryption_keys, rounds);
            let mut recovered = [0_u8; BLOCK_BYTES];
            decrypt_block(&decryption_keys, rounds, &ciphertext, &mut recovered);

            assert_ne!(ciphertext, plaintext, "key length {key_len}");
            assert_eq!(recovered, plaintext, "key length {key_len}");
        }
    }

    #[test]
    fn only_the_three_standard_key_lengths_are_accepted() {
        assert_eq!(rounds_for(16), Some(10));
        assert_eq!(rounds_for(24), Some(12));
        assert_eq!(rounds_for(32), Some(14));
        for key_len in [0, 8, 15, 17, 23, 25, 31, 33, 64] {
            assert_eq!(rounds_for(key_len), None, "key length {key_len}");
        }
    }
}
