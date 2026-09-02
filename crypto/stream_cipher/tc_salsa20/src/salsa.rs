//! Salsa20 state and block function.

use tc_cipher::StreamError;

use crate::BLOCK_BYTES;

pub(crate) const STATE_WORDS: usize = 16;

const TAU: [u32; 4] = [0x6170_7865, 0x3120_646e, 0x7962_2d36, 0x6b20_6574];
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

pub(crate) struct State {
    rounds: usize,
    pub(crate) words: [u32; STATE_WORDS],
    key_stream: [u8; BLOCK_BYTES],
    index: usize,
    limit_word0: u32,
    limit_word1: u32,
    limit_word2: u32,
    initialised: bool,
}

impl State {
    pub(crate) const fn new(rounds: usize) -> Self {
        Self {
            rounds,
            words: [0; STATE_WORDS],
            key_stream: [0; BLOCK_BYTES],
            index: 0,
            limit_word0: 0,
            limit_word1: 0,
            limit_word2: 0,
            initialised: false,
        }
    }

    pub(crate) fn init(&mut self, key: &[u8], iv: &[u8]) {
        self.words.fill(0);
        set_key(&mut self.words, key, iv);
        self.finish_initialization();
    }

    pub(crate) fn finish_initialization(&mut self) {
        self.reset();
        self.initialised = true;
    }

    pub(crate) fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        if self.limit_exceeded_by(1) {
            return Err(StreamError::MaxBytesExceeded);
        }
        Ok(input ^ self.next_byte())
    }

    pub(crate) fn process_bytes(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, StreamError> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        if output.len() < input.len() {
            return Err(StreamError::BufferTooShort);
        }
        if self.limit_exceeded_by(input.len()) {
            return Err(StreamError::MaxBytesExceeded);
        }

        for (input, output) in input.iter().zip(output.iter_mut()) {
            *output = *input ^ self.next_byte();
        }
        Ok(input.len())
    }

    pub(crate) fn reset(&mut self) {
        self.index = 0;
        self.limit_word0 = 0;
        self.limit_word1 = 0;
        self.limit_word2 = 0;
        self.words[8] = 0;
        self.words[9] = 0;
    }

    fn next_byte(&mut self) -> u8 {
        if self.index == 0 {
            let output = block(self.rounds, &self.words);
            for (bytes, word) in self.key_stream.chunks_exact_mut(4).zip(output) {
                bytes.copy_from_slice(&word.to_le_bytes());
            }
            self.words[8] = self.words[8].wrapping_add(1);
            if self.words[8] == 0 {
                self.words[9] = self.words[9].wrapping_add(1);
            }
        }
        let output = self.key_stream[self.index];
        self.index = (self.index + 1) & (BLOCK_BYTES - 1);
        output
    }

    fn limit_exceeded_by(&mut self, mut length: usize) -> bool {
        while length != 0 {
            let chunk = length.min(u32::MAX as usize) as u32;
            let previous = self.limit_word0;
            self.limit_word0 = self.limit_word0.wrapping_add(chunk);
            if self.limit_word0 < previous {
                self.limit_word1 = self.limit_word1.wrapping_add(1);
                if self.limit_word1 == 0 {
                    self.limit_word2 = self.limit_word2.wrapping_add(1);
                }
            }
            length -= chunk as usize;
        }
        self.limit_word2 & 0x20 != 0
    }
}

pub(crate) fn set_key(state: &mut [u32; STATE_WORDS], key: &[u8], iv: &[u8]) {
    let constants = if key.len() == 16 { TAU } else { SIGMA };
    state[0] = constants[0];
    state[5] = constants[1];
    state[10] = constants[2];
    state[15] = constants[3];

    for (index, bytes) in key[..16].chunks_exact(4).enumerate() {
        state[1 + index] = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    for (index, bytes) in key[key.len() - 16..].chunks_exact(4).enumerate() {
        state[11 + index] = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    for (index, bytes) in iv[..8].chunks_exact(4).enumerate() {
        state[6 + index] = u32::from_le_bytes(bytes.try_into().unwrap());
    }
}

pub(crate) fn block(rounds: usize, input: &[u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut state = *input;
    for _ in (0..rounds).step_by(2) {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 5, 9, 13, 1);
        quarter_round(&mut state, 10, 14, 2, 6);
        quarter_round(&mut state, 15, 3, 7, 11);

        quarter_round(&mut state, 0, 1, 2, 3);
        quarter_round(&mut state, 5, 6, 7, 4);
        quarter_round(&mut state, 10, 11, 8, 9);
        quarter_round(&mut state, 15, 12, 13, 14);
    }
    for (word, original) in state.iter_mut().zip(input) {
        *word = word.wrapping_add(*original);
    }
    state
}

#[inline]
fn quarter_round(
    state: &mut [u32; STATE_WORDS],
    a_index: usize,
    b_index: usize,
    c_index: usize,
    d_index: usize,
) {
    let (mut a, mut b, mut c, mut d) = (
        state[a_index],
        state[b_index],
        state[c_index],
        state[d_index],
    );
    b ^= a.wrapping_add(d).rotate_left(7);
    c ^= b.wrapping_add(a).rotate_left(9);
    d ^= c.wrapping_add(b).rotate_left(13);
    a ^= d.wrapping_add(c).rotate_left(18);
    state[a_index] = a;
    state[b_index] = b;
    state[c_index] = c;
    state[d_index] = d;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_limit_boundary_is_enforced() {
        let mut state = State::new(20);
        state.limit_word0 = u32::MAX;
        state.limit_word1 = u32::MAX;
        state.limit_word2 = 0x1f;
        assert!(state.limit_exceeded_by(1));
    }
}
