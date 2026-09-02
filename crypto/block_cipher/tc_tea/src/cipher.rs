//! TEA and XTEA round functions and block transformations.

use crate::{BLOCK_BYTES, KEY_BYTES};

/// The golden-ratio round constant both ciphers are built on.
const DELTA: u32 = 0x9e37_79b9;
/// Number of rounds; both ciphers use the same count.
pub(crate) const ROUNDS: usize = 32;
/// Number of 32-bit words in a key.
const KEY_WORDS: usize = KEY_BYTES / 4;

/// Splits the key into its big-endian 32-bit words.
fn key_words(key: &[u8; KEY_BYTES]) -> [u32; KEY_WORDS] {
    let mut words = [0_u32; KEY_WORDS];
    for (word, chunk) in words.iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    words
}

/// Reads the two big-endian halves of a block.
fn read_halves(input: &[u8; BLOCK_BYTES]) -> (u32, u32) {
    (
        u32::from_be_bytes(input[0..4].try_into().unwrap()),
        u32::from_be_bytes(input[4..8].try_into().unwrap()),
    )
}

/// Writes the two halves back into a block.
fn write_halves(v0: u32, v1: u32, output: &mut [u8; BLOCK_BYTES]) {
    output[0..4].copy_from_slice(&v0.to_be_bytes());
    output[4..8].copy_from_slice(&v1.to_be_bytes());
}

/// TEA: the key words are used directly, two per Feistel half.
pub(crate) mod tea {
    use super::{BLOCK_BYTES, DELTA, KEY_BYTES, KEY_WORDS, ROUNDS};
    use super::{key_words, read_halves, write_halves};

    /// The sum decryption starts from, having been accumulated over all rounds.
    const FINAL_SUM: u32 = DELTA.wrapping_mul(ROUNDS as u32);

    pub(crate) fn expand_key(key: &[u8; KEY_BYTES]) -> [u32; KEY_WORDS] {
        key_words(key)
    }

    pub(crate) fn encrypt_block(
        key: &[u32; KEY_WORDS],
        input: &[u8; BLOCK_BYTES],
        output: &mut [u8; BLOCK_BYTES],
    ) {
        let (mut v0, mut v1) = read_halves(input);
        let mut sum = 0_u32;
        for _ in 0..ROUNDS {
            sum = sum.wrapping_add(DELTA);
            v0 = v0.wrapping_add(feistel(v1, sum, key[0], key[1]));
            v1 = v1.wrapping_add(feistel(v0, sum, key[2], key[3]));
        }
        write_halves(v0, v1, output);
    }

    pub(crate) fn decrypt_block(
        key: &[u32; KEY_WORDS],
        input: &[u8; BLOCK_BYTES],
        output: &mut [u8; BLOCK_BYTES],
    ) {
        let (mut v0, mut v1) = read_halves(input);
        let mut sum = FINAL_SUM;
        for _ in 0..ROUNDS {
            v1 = v1.wrapping_sub(feistel(v0, sum, key[2], key[3]));
            v0 = v0.wrapping_sub(feistel(v1, sum, key[0], key[1]));
            sum = sum.wrapping_sub(DELTA);
        }
        write_halves(v0, v1, output);
    }

    /// One half of a TEA round.
    fn feistel(x: u32, sum: u32, k0: u32, k1: u32) -> u32 {
        (x << 4).wrapping_add(k0) ^ x.wrapping_add(sum) ^ (x >> 5).wrapping_add(k1)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_final_sum_matches_the_published_constant() {
            assert_eq!(FINAL_SUM, 0xc6ef_3720);
        }
    }
}

/// XTEA: the round constant selects which key word each half sees, which is
/// what repairs TEA's key schedule.
pub(crate) mod xtea {
    use super::{BLOCK_BYTES, DELTA, KEY_BYTES, ROUNDS};
    use super::{key_words, read_halves, write_halves};

    /// One `[sum0, sum1]` pair per round.
    pub(crate) type Schedule = [[u32; 2]; ROUNDS];

    pub(crate) fn expand_key(key: &[u8; KEY_BYTES]) -> Schedule {
        let words = key_words(key);
        let mut schedule = [[0_u32; 2]; ROUNDS];
        let mut sum = 0_u32;
        for round in &mut schedule {
            // 兩個位置各用 sum 的不同位元來選金鑰字。
            round[0] = sum.wrapping_add(words[(sum & 3) as usize]);
            sum = sum.wrapping_add(DELTA);
            round[1] = sum.wrapping_add(words[((sum >> 11) & 3) as usize]);
        }
        schedule
    }

    pub(crate) fn encrypt_block(
        schedule: &Schedule,
        input: &[u8; BLOCK_BYTES],
        output: &mut [u8; BLOCK_BYTES],
    ) {
        let (mut v0, mut v1) = read_halves(input);
        for round in schedule {
            v0 = v0.wrapping_add(mix(v1) ^ round[0]);
            v1 = v1.wrapping_add(mix(v0) ^ round[1]);
        }
        write_halves(v0, v1, output);
    }

    pub(crate) fn decrypt_block(
        schedule: &Schedule,
        input: &[u8; BLOCK_BYTES],
        output: &mut [u8; BLOCK_BYTES],
    ) {
        let (mut v0, mut v1) = read_halves(input);
        for round in schedule.iter().rev() {
            v1 = v1.wrapping_sub(mix(v0) ^ round[1]);
            v0 = v0.wrapping_sub(mix(v1) ^ round[0]);
        }
        write_halves(v0, v1, output);
    }

    /// The round mixing function.
    fn mix(x: u32) -> u32 {
        ((x << 4) ^ (x >> 5)).wrapping_add(x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_BYTES] = [
        0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78,
        0x9a,
    ];
    const PLAINTEXT: [u8; BLOCK_BYTES] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    #[test]
    fn tea_round_trips() {
        let key = tea::expand_key(&KEY);
        let mut ciphertext = [0_u8; BLOCK_BYTES];
        let mut recovered = [0_u8; BLOCK_BYTES];
        tea::encrypt_block(&key, &PLAINTEXT, &mut ciphertext);
        tea::decrypt_block(&key, &ciphertext, &mut recovered);
        assert_ne!(ciphertext, PLAINTEXT);
        assert_eq!(recovered, PLAINTEXT);
    }

    #[test]
    fn xtea_round_trips() {
        let schedule = xtea::expand_key(&KEY);
        let mut ciphertext = [0_u8; BLOCK_BYTES];
        let mut recovered = [0_u8; BLOCK_BYTES];
        xtea::encrypt_block(&schedule, &PLAINTEXT, &mut ciphertext);
        xtea::decrypt_block(&schedule, &ciphertext, &mut recovered);
        assert_ne!(ciphertext, PLAINTEXT);
        assert_eq!(recovered, PLAINTEXT);
    }

    #[test]
    fn the_two_ciphers_differ() {
        // XTEA 不是 TEA 的相容變體。
        let mut tea_out = [0_u8; BLOCK_BYTES];
        let mut xtea_out = [0_u8; BLOCK_BYTES];
        tea::encrypt_block(&tea::expand_key(&KEY), &PLAINTEXT, &mut tea_out);
        xtea::encrypt_block(&xtea::expand_key(&KEY), &PLAINTEXT, &mut xtea_out);
        assert_ne!(tea_out, xtea_out);
    }
}
