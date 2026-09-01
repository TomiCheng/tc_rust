//! Noekeon round functions and block transformations.

use crate::{BLOCK_BYTES, KEY_BYTES};

/// Number of rounds; a seventeenth round constant drives the output transform.
const ROUNDS: usize = 16;

/// Round constants, consumed in ascending order when encrypting and descending
/// order when decrypting.
const ROUND_CONSTANTS: [u8; ROUNDS + 1] = [
    0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4,
];

/// Derives the working key for the requested direction.
///
/// Direct-key mode uses the key words unchanged when encrypting; decryption
/// runs `theta` over them with a zero key first.
pub(crate) fn prepare_key(for_encryption: bool, key: &[u8; KEY_BYTES]) -> [u32; 4] {
    let mut working_key = read_words(key);
    if !for_encryption {
        theta(&mut working_key, &[0; 4]);
    }
    working_key
}

pub(crate) fn encrypt_block(
    working_key: &[u32; 4],
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) {
    let mut state = read_words(input);

    for &constant in &ROUND_CONSTANTS[..ROUNDS] {
        state[0] ^= u32::from(constant);
        theta(&mut state, working_key);
        pi1(&mut state);
        gamma(&mut state);
        pi2(&mut state);
    }

    // 輸出轉換:最後一個常數與一次 theta,沒有非線性層。
    state[0] ^= u32::from(ROUND_CONSTANTS[ROUNDS]);
    theta(&mut state, working_key);

    write_words(&state, output);
}

pub(crate) fn decrypt_block(
    working_key: &[u32; 4],
    input: &[u8; BLOCK_BYTES],
    output: &mut [u8; BLOCK_BYTES],
) {
    let mut state = read_words(input);

    // 每一輪的次序整個顛倒:theta 先於常數,常數也由後往前取。
    for &constant in ROUND_CONSTANTS[1..].iter().rev() {
        theta(&mut state, working_key);
        state[0] ^= u32::from(constant);
        pi1(&mut state);
        gamma(&mut state);
        pi2(&mut state);
    }

    theta(&mut state, working_key);
    state[0] ^= u32::from(ROUND_CONSTANTS[0]);

    write_words(&state, output);
}

/// Reads four big-endian words from a block.
fn read_words(input: &[u8; BLOCK_BYTES]) -> [u32; 4] {
    let mut words = [0_u32; 4];
    for (word, chunk) in words.iter_mut().zip(input.chunks_exact(4)) {
        *word = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    words
}

/// Writes four words back into a block as big-endian bytes.
fn write_words(words: &[u32; 4], output: &mut [u8; BLOCK_BYTES]) {
    for (word, chunk) in words.iter().zip(output.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
}

/// The linear diffusion layer, which also mixes in the working key.
fn theta(state: &mut [u32; 4], working_key: &[u32; 4]) {
    let mut t02 = state[0] ^ state[2];
    t02 ^= t02.rotate_left(8) ^ t02.rotate_left(24);

    for (word, key_word) in state.iter_mut().zip(working_key) {
        *word ^= key_word;
    }

    let mut t13 = state[1] ^ state[3];
    t13 ^= t13.rotate_left(8) ^ t13.rotate_left(24);

    state[0] ^= t13;
    state[1] ^= t02;
    state[2] ^= t13;
    state[3] ^= t02;
}

/// The first bit-shuffle layer.
fn pi1(state: &mut [u32; 4]) {
    state[1] = state[1].rotate_left(1);
    state[2] = state[2].rotate_left(5);
    state[3] = state[3].rotate_left(2);
}

/// The second bit-shuffle layer, undoing the rotations of [`pi1`].
fn pi2(state: &mut [u32; 4]) {
    state[1] = state[1].rotate_right(1);
    state[2] = state[2].rotate_right(5);
    state[3] = state[3].rotate_right(2);
}

/// The nonlinear layer, an involution.
fn gamma(state: &mut [u32; 4]) {
    let original3 = state[3];

    state[1] ^= state[3] | state[2];
    state[3] = state[0] ^ (state[2] & !state[1]);
    state[2] = original3 ^ !state[1] ^ state[2] ^ state[3];
    state[1] ^= state[3] | state[2];
    state[0] = original3 ^ (state[2] & state[1]);
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATE: [u32; 4] = [0x0123_4567, 0x89ab_cdef, 0xfedc_ba98, 0x7654_3210];

    #[test]
    fn gamma_is_an_involution() {
        let mut state = STATE;
        gamma(&mut state);
        assert_ne!(state, STATE);
        gamma(&mut state);
        assert_eq!(state, STATE);
    }

    #[test]
    fn pi2_undoes_pi1() {
        let mut state = STATE;
        pi1(&mut state);
        assert_ne!(state, STATE);
        pi2(&mut state);
        assert_eq!(state, STATE);
    }

    #[test]
    fn theta_with_a_zero_key_is_an_involution() {
        // 解密工作金鑰正是靠這個性質推得:theta 的線性部分自身互逆。
        let mut state = STATE;
        theta(&mut state, &[0; 4]);
        assert_ne!(state, STATE);
        theta(&mut state, &[0; 4]);
        assert_eq!(state, STATE);
    }
}
