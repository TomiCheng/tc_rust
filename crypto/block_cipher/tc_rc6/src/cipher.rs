//! RC6 key schedule and block transforms.

use crate::{MAX_KEY_BYTES, ROUNDS};

/// Maximum words needed to hold a supported key.
const MAX_KEY_WORDS: usize = MAX_KEY_BYTES.div_ceil(4);
/// Magic constant `Odd((e - 2) * 2^32)`.
const P32: u32 = 0xb7e1_5163;
/// Magic constant `Odd((phi - 1) * 2^32)`.
const Q32: u32 = 0x9e37_79b9;
/// Number of expanded-key words.
pub(crate) const SUBKEYS: usize = 2 * ROUNDS + 4;

/// Expands a key into the forty-four RC6 working words.
pub(crate) fn expand_key(key: &[u8]) -> [u32; SUBKEYS] {
    let key_words = key.len().div_ceil(4);
    let mut words_buffer = [0u32; MAX_KEY_WORDS];
    let words = &mut words_buffer[..key_words];
    for (word, bytes) in words.iter_mut().zip(key.chunks(4)) {
        let mut value = [0u8; 4];
        value[..bytes.len()].copy_from_slice(bytes);
        *word = u32::from_le_bytes(value);
    }

    let mut subkeys = [0u32; SUBKEYS];
    subkeys[0] = P32;
    for index in 1..SUBKEYS {
        subkeys[index] = subkeys[index - 1].wrapping_add(Q32);
    }

    let iterations = 3 * SUBKEYS.max(key_words);
    let (mut a, mut b) = (0u32, 0u32);
    let (mut subkey_index, mut key_index) = (0usize, 0usize);
    for _ in 0..iterations {
        a = subkeys[subkey_index]
            .wrapping_add(a)
            .wrapping_add(b)
            .rotate_left(3);
        subkeys[subkey_index] = a;

        let rotation = a.wrapping_add(b);
        b = words[key_index]
            .wrapping_add(a)
            .wrapping_add(b)
            .rotate_left(rotation);
        words[key_index] = b;

        subkey_index = (subkey_index + 1) % SUBKEYS;
        key_index = (key_index + 1) % key_words;
    }
    subkeys
}

pub(crate) fn encrypt(subkeys: &[u32; SUBKEYS], input: &[u8; 16], output: &mut [u8; 16]) {
    let [mut a, mut b, mut c, mut d] = read_block(input);

    b = b.wrapping_add(subkeys[0]);
    d = d.wrapping_add(subkeys[1]);

    for round in 1..=ROUNDS {
        let t = mix(b).rotate_left(5);
        let u = mix(d).rotate_left(5);
        a = (a ^ t).rotate_left(u).wrapping_add(subkeys[2 * round]);
        c = (c ^ u).rotate_left(t).wrapping_add(subkeys[2 * round + 1]);
        (a, b, c, d) = (b, c, d, a);
    }

    a = a.wrapping_add(subkeys[2 * ROUNDS + 2]);
    c = c.wrapping_add(subkeys[2 * ROUNDS + 3]);
    write_block(output, [a, b, c, d]);
}

pub(crate) fn decrypt(subkeys: &[u32; SUBKEYS], input: &[u8; 16], output: &mut [u8; 16]) {
    let [mut a, mut b, mut c, mut d] = read_block(input);

    c = c.wrapping_sub(subkeys[2 * ROUNDS + 3]);
    a = a.wrapping_sub(subkeys[2 * ROUNDS + 2]);

    for round in (1..=ROUNDS).rev() {
        (a, b, c, d) = (d, a, b, c);
        let t = mix(b).rotate_left(5);
        let u = mix(d).rotate_left(5);
        c = c.wrapping_sub(subkeys[2 * round + 1]).rotate_right(t) ^ u;
        a = a.wrapping_sub(subkeys[2 * round]).rotate_right(u) ^ t;
    }

    d = d.wrapping_sub(subkeys[1]);
    b = b.wrapping_sub(subkeys[0]);
    write_block(output, [a, b, c, d]);
}

fn mix(value: u32) -> u32 {
    value.wrapping_mul(value.wrapping_mul(2).wrapping_add(1))
}

fn read_block(input: &[u8; 16]) -> [u32; 4] {
    let mut words = [0u32; 4];
    for (word, bytes) in words.iter_mut().zip(input.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    words
}

fn write_block(output: &mut [u8; 16], words: [u32; 4]) {
    for (word, bytes) in words.iter().zip(output.chunks_exact_mut(4)) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
}
