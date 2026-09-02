//! Per-variant Threefish round functions.
//!
//! Bouncy Castle uses separately unrolled implementations. This implementation
//! follows the same specification using rotation and permutation tables.

/// Key-schedule parity constant from Skein 1.3.
pub(crate) const C_240: u64 = 0x1bd1_1bda_a9fc_1a22;

#[rustfmt::skip]
const ROT_256: [u32; 16] = [
    14, 16,  52, 57,  23, 40,   5, 37,
    25, 33,  46, 12,  58, 22,  32, 32,
];

#[rustfmt::skip]
const ROT_512: [u32; 32] = [
    46, 36, 19, 37,
    33, 27, 14, 42,
    17, 49, 36, 39,
    44,  9, 54, 56,
    39, 30, 34, 24,
    13, 50, 10, 17,
    25, 29, 39, 43,
     8, 35, 56, 22,
];

#[rustfmt::skip]
const ROT_1024: [u32; 64] = [
    24, 13,  8, 47,  8, 17, 22, 37,
    38, 19, 10, 55, 49, 18, 23, 52,
    33,  4, 51, 13, 34, 41, 59, 17,
     5, 20, 48, 41, 47, 28, 16, 25,
    41,  9, 37, 31, 12, 47, 44, 30,
    16, 34, 56, 51,  4, 53, 42, 41,
    31, 44, 47, 46, 19, 42, 44, 25,
     9, 48, 35, 52, 23, 31, 37, 20,
];

const PERM_256: [usize; 4] = [0, 3, 2, 1];
const PERM_512: [usize; 8] = [2, 1, 4, 7, 6, 5, 0, 3];
const PERM_1024: [usize; 16] = [0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1];

pub(crate) struct Variant {
    rounds: usize,
    rotations: &'static [u32],
    permutation: &'static [usize],
}

pub(crate) fn variant(words: usize) -> Variant {
    match words {
        4 => Variant {
            rounds: 72,
            rotations: &ROT_256,
            permutation: &PERM_256,
        },
        8 => Variant {
            rounds: 72,
            rotations: &ROT_512,
            permutation: &PERM_512,
        },
        16 => Variant {
            rounds: 80,
            rotations: &ROT_1024,
            permutation: &PERM_1024,
        },
        _ => unreachable!("ThreefishEngine validates WORDS"),
    }
}

#[inline]
fn subkey_word<const WORDS: usize>(
    key: &[u64; WORDS],
    parity: u64,
    tweak: &[u64; 3],
    subkey: usize,
    word: usize,
) -> u64 {
    let index = (subkey + word) % (WORDS + 1);
    let base = if index == WORDS { parity } else { key[index] };
    if word == WORDS - 3 {
        base.wrapping_add(tweak[subkey % 3])
    } else if word == WORDS - 2 {
        base.wrapping_add(tweak[(subkey + 1) % 3])
    } else if word == WORDS - 1 {
        base.wrapping_add(subkey as u64)
    } else {
        base
    }
}

pub(crate) fn encrypt<const WORDS: usize>(
    variant: &Variant,
    key: &[u64; WORDS],
    parity: u64,
    tweak: &[u64; 3],
    input: &[u64; WORDS],
    output: &mut [u64; WORDS],
) {
    let Variant {
        rounds,
        rotations,
        permutation,
    } = *variant;
    let pairs = WORDS / 2;
    let mut state = *input;

    for (word, value) in state.iter_mut().enumerate() {
        *value = value.wrapping_add(subkey_word(key, parity, tweak, 0, word));
    }

    for round in 0..rounds {
        let rotations = &rotations[(round % 8) * pairs..(round % 8 + 1) * pairs];
        for pair in 0..pairs {
            let first = state[2 * pair];
            let second = state[2 * pair + 1];
            let sum = first.wrapping_add(second);
            state[2 * pair] = sum;
            state[2 * pair + 1] = second.rotate_left(rotations[pair]) ^ sum;
        }

        let mut permuted = [0u64; WORDS];
        for word in 0..WORDS {
            permuted[word] = state[permutation[word]];
        }
        state = permuted;

        if (round + 1) % 4 == 0 {
            let subkey = (round + 1) / 4;
            for (word, value) in state.iter_mut().enumerate() {
                *value = value.wrapping_add(subkey_word(key, parity, tweak, subkey, word));
            }
        }
    }

    *output = state;
}

pub(crate) fn decrypt<const WORDS: usize>(
    variant: &Variant,
    key: &[u64; WORDS],
    parity: u64,
    tweak: &[u64; 3],
    input: &[u64; WORDS],
    output: &mut [u64; WORDS],
) {
    let Variant {
        rounds,
        rotations,
        permutation,
    } = *variant;
    let pairs = WORDS / 2;
    let mut state = *input;

    for round in (0..rounds).rev() {
        if (round + 1) % 4 == 0 {
            let subkey = (round + 1) / 4;
            for (word, value) in state.iter_mut().enumerate() {
                *value = value.wrapping_sub(subkey_word(key, parity, tweak, subkey, word));
            }
        }

        let mut unpermuted = [0u64; WORDS];
        for word in 0..WORDS {
            unpermuted[permutation[word]] = state[word];
        }
        state = unpermuted;

        let rotations = &rotations[(round % 8) * pairs..(round % 8 + 1) * pairs];
        for pair in 0..pairs {
            let sum = state[2 * pair];
            let mixed = state[2 * pair + 1];
            let second = (sum ^ mixed).rotate_right(rotations[pair]);
            state[2 * pair] = sum.wrapping_sub(second);
            state[2 * pair + 1] = second;
        }
    }

    for (word, value) in state.iter_mut().enumerate() {
        *value = value.wrapping_sub(subkey_word(key, parity, tweak, 0, word));
    }
    *output = state;
}
