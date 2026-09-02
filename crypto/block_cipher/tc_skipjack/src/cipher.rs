//! SKIPJACK key schedule, permutations, and block transformations.

use crate::{BLOCK_BYTES, KEY_BYTES};

/// Number of steps; the two rules alternate in runs of [`RULE_RUN`].
pub(crate) const STEPS: usize = 32;
/// Consecutive steps applied under one rule before switching to the other.
const RULE_RUN: usize = 8;
/// Key bytes consumed per step.
const STEP_KEY_BYTES: usize = 4;

/// One step's slice of the expanded key.
pub(crate) type Schedule = [[u8; STEP_KEY_BYTES]; STEPS];

/// The SKIPJACK F-table (byte substitution).
#[rustfmt::skip]
const FTABLE: [u8; 256] = [
    0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
    0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
    0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
    0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
    0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
    0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
    0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
    0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
    0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
    0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
    0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
    0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
    0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
    0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
    0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
    0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46,
];

/// Expands the 80-bit key by cycling its bytes four at a time across the steps.
pub(crate) fn expand_key(key: &[u8; KEY_BYTES]) -> Schedule {
    let mut schedule = [[0_u8; STEP_KEY_BYTES]; STEPS];
    for (step, step_key) in schedule.iter_mut().enumerate() {
        for (index, byte) in step_key.iter_mut().enumerate() {
            *byte = key[(step * STEP_KEY_BYTES + index) % KEY_BYTES];
        }
    }
    schedule
}

pub(crate) fn encrypt_block(
    schedule: &Schedule,
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) {
    let [mut w1, mut w2, mut w3, mut w4] = read_words(input);

    let mut steps = 0..STEPS;
    for _ in 0..2 {
        for step in steps.by_ref().take(RULE_RUN) {
            // Rule A
            let previous = w4;
            w4 = w3;
            w3 = w2;
            w2 = g(&schedule[step], w1);
            w1 = w2 ^ previous ^ counter(step);
        }
        for step in steps.by_ref().take(RULE_RUN) {
            // Rule B
            let previous = w4;
            w4 = w3;
            w3 = w1 ^ w2 ^ counter(step);
            w2 = g(&schedule[step], w1);
            w1 = previous;
        }
    }

    write_words([w1, w2, w3, w4], output);
}

pub(crate) fn decrypt_block(
    schedule: &Schedule,
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) {
    // 解密時字的角色互換,且步數由後往前;`g` 換成它的反置換 `h`。
    let [mut w2, mut w1, mut w4, mut w3] = read_words(input);

    let mut steps = (0..STEPS).rev();
    for _ in 0..2 {
        for step in steps.by_ref().take(RULE_RUN) {
            let previous = w4;
            w4 = w3;
            w3 = w2;
            w2 = h(&schedule[step], w1);
            w1 = w2 ^ previous ^ counter(step);
        }
        for step in steps.by_ref().take(RULE_RUN) {
            let previous = w4;
            w4 = w3;
            w3 = w1 ^ w2 ^ counter(step);
            w2 = h(&schedule[step], w1);
            w1 = previous;
        }
    }

    write_words([w2, w1, w4, w3], output);
}

/// The step counter mixed into both rules, numbered from one.
fn counter(step: usize) -> u16 {
    step as u16 + 1
}

/// The keyed `G` permutation: four F-table rounds over the two bytes of `w`.
fn g(step_key: &[u8; STEP_KEY_BYTES], w: u16) -> u16 {
    let g1 = (w >> 8) as u8;
    let g2 = w as u8;
    let g3 = FTABLE[(g2 ^ step_key[0]) as usize] ^ g1;
    let g4 = FTABLE[(g3 ^ step_key[1]) as usize] ^ g2;
    let g5 = FTABLE[(g4 ^ step_key[2]) as usize] ^ g3;
    let g6 = FTABLE[(g5 ^ step_key[3]) as usize] ^ g4;
    u16::from_be_bytes([g5, g6])
}

/// The inverse permutation `H`: the same rounds with the key bytes reversed.
fn h(step_key: &[u8; STEP_KEY_BYTES], w: u16) -> u16 {
    let h1 = w as u8;
    let h2 = (w >> 8) as u8;
    let h3 = FTABLE[(h2 ^ step_key[3]) as usize] ^ h1;
    let h4 = FTABLE[(h3 ^ step_key[2]) as usize] ^ h2;
    let h5 = FTABLE[(h4 ^ step_key[1]) as usize] ^ h3;
    let h6 = FTABLE[(h5 ^ step_key[0]) as usize] ^ h4;
    u16::from_be_bytes([h6, h5])
}

/// Reads the four big-endian 16-bit words of a block.
fn read_words(input: &[u8; BLOCK_BYTES]) -> [u16; 4] {
    let mut words = [0_u16; 4];
    for (word, chunk) in words.iter_mut().zip(input.chunks_exact(2)) {
        *word = u16::from_be_bytes(chunk.try_into().unwrap());
    }
    words
}

/// Writes four words back into a block as big-endian bytes.
fn write_words(words: [u16; 4], output: &mut [u8; BLOCK_BYTES]) {
    for (word, chunk) in words.iter().zip(output.chunks_exact_mut(2)) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_f_table_is_a_permutation() {
        let mut seen = [false; 256];
        for &value in &FTABLE {
            assert!(!seen[usize::from(value)], "duplicate entry {value:#04x}");
            seen[usize::from(value)] = true;
        }
    }

    #[test]
    fn h_inverts_g_for_every_word() {
        let step_key = [0x12, 0x34, 0x56, 0x78];
        for word in 0..=u16::MAX {
            assert_eq!(h(&step_key, g(&step_key, word)), word, "word = {word:#06x}");
        }
    }

    #[test]
    fn the_schedule_cycles_the_key_bytes() {
        let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let schedule = expand_key(&key);
        assert_eq!(schedule[0], [0, 1, 2, 3]);
        assert_eq!(schedule[1], [4, 5, 6, 7]);
        // 第三步跨過金鑰結尾繞回開頭。
        assert_eq!(schedule[2], [8, 9, 0, 1]);
    }
}
