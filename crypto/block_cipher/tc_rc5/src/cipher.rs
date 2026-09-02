//! Shared RC5 key schedule and block transforms.

use crate::{MAX_KEY_BYTES, MAX_ROUNDS};

const MAX_KEY_WORDS: usize = MAX_KEY_BYTES.div_ceil(4);
const MAX_SUBKEYS: usize = 2 * (MAX_ROUNDS + 1);

pub(crate) trait Word: Copy {
    const BYTES: usize;
    const P: Self;
    const Q: Self;
    const ZERO: Self;

    fn add(self, other: Self) -> Self;
    fn sub(self, other: Self) -> Self;
    fn xor(self, other: Self) -> Self;
    fn rotate_left(self, count: u32) -> Self;
    fn rotate_right(self, count: u32) -> Self;
    fn rotation(self) -> u32;
    fn read_le(input: &[u8]) -> Self;
    fn write_le(self, output: &mut [u8]);
}

macro_rules! impl_word {
    ($word:ty, $bytes:literal, $p:literal, $q:literal) => {
        impl Word for $word {
            const BYTES: usize = $bytes;
            const P: Self = $p;
            const Q: Self = $q;
            const ZERO: Self = 0;

            fn add(self, other: Self) -> Self {
                self.wrapping_add(other)
            }

            fn sub(self, other: Self) -> Self {
                self.wrapping_sub(other)
            }

            fn xor(self, other: Self) -> Self {
                self ^ other
            }

            fn rotate_left(self, count: u32) -> Self {
                Self::rotate_left(self, count)
            }

            fn rotate_right(self, count: u32) -> Self {
                Self::rotate_right(self, count)
            }

            fn rotation(self) -> u32 {
                self as u32
            }

            fn read_le(input: &[u8]) -> Self {
                Self::from_le_bytes(input[..$bytes].try_into().unwrap())
            }

            fn write_le(self, output: &mut [u8]) {
                output[..$bytes].copy_from_slice(&self.to_le_bytes());
            }
        }
    };
}

impl_word!(u32, 4, 0xb7e1_5163, 0x9e37_79b9);
impl_word!(u64, 8, 0xb7e1_5162_8aed_2a6b, 0x9e37_79b9_7f4a_7c15);

pub(crate) struct Core<W: Word> {
    subkeys: [W; MAX_SUBKEYS],
    rounds: usize,
}

impl<W: Word> Core<W> {
    pub(crate) fn new() -> Self {
        Self {
            subkeys: [W::ZERO; MAX_SUBKEYS],
            rounds: 0,
        }
    }

    pub(crate) fn expand_key(&mut self, key: &[u8], rounds: usize) {
        let key_words = key.len().div_ceil(W::BYTES);
        let mut words = [W::ZERO; MAX_KEY_WORDS];
        for (word, bytes) in words[..key_words].iter_mut().zip(key.chunks(W::BYTES)) {
            let mut value = [0u8; 8];
            value[..bytes.len()].copy_from_slice(bytes);
            *word = W::read_le(&value);
        }

        let subkey_count = 2 * (rounds + 1);
        self.subkeys[0] = W::P;
        for index in 1..subkey_count {
            self.subkeys[index] = self.subkeys[index - 1].add(W::Q);
        }

        let iterations = 3 * subkey_count.max(key_words);
        let (mut a, mut b) = (W::ZERO, W::ZERO);
        let (mut subkey_index, mut key_index) = (0usize, 0usize);
        for _ in 0..iterations {
            a = self.subkeys[subkey_index].add(a).add(b).rotate_left(3);
            self.subkeys[subkey_index] = a;

            let rotation = a.add(b);
            b = words[key_index]
                .add(a)
                .add(b)
                .rotate_left(rotation.rotation());
            words[key_index] = b;

            subkey_index = (subkey_index + 1) % subkey_count;
            key_index = (key_index + 1) % key_words;
        }
        self.rounds = rounds;
    }

    pub(crate) fn encrypt(&self, input: &[u8], output: &mut [u8]) {
        let bytes = W::BYTES;
        let mut a = W::read_le(input).add(self.subkeys[0]);
        let mut b = W::read_le(&input[bytes..]).add(self.subkeys[1]);
        for round in 1..=self.rounds {
            a = a
                .xor(b)
                .rotate_left(b.rotation())
                .add(self.subkeys[2 * round]);
            b = b
                .xor(a)
                .rotate_left(a.rotation())
                .add(self.subkeys[2 * round + 1]);
        }
        a.write_le(output);
        b.write_le(&mut output[bytes..]);
    }

    pub(crate) fn decrypt(&self, input: &[u8], output: &mut [u8]) {
        let bytes = W::BYTES;
        let mut a = W::read_le(input);
        let mut b = W::read_le(&input[bytes..]);
        for round in (1..=self.rounds).rev() {
            b = b
                .sub(self.subkeys[2 * round + 1])
                .rotate_right(a.rotation())
                .xor(a);
            a = a
                .sub(self.subkeys[2 * round])
                .rotate_right(b.rotation())
                .xor(b);
        }
        a.sub(self.subkeys[0]).write_le(output);
        b.sub(self.subkeys[1]).write_le(&mut output[bytes..]);
    }
}
