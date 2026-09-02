//! ChaCha block function.

use crate::BLOCK_BYTES;
use tc_cipher::StreamError;

pub(crate) const STATE_WORDS: usize = 16;

const TAU: [u32; 4] = [0x6170_7865, 0x3120_646e, 0x7962_2d36, 0x6b20_6574];
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[derive(Clone, Copy)]
pub(crate) enum Counter {
    Original,
    Ietf,
}

pub(crate) struct State {
    rounds: usize,
    pub(crate) words: [u32; STATE_WORDS],
    key_stream: [u8; BLOCK_BYTES],
    index: usize,
    limit_word0: u32,
    limit_word1: u32,
    limit_word2: u32,
    counter: Counter,
    counter_exhausted: bool,
    initialised: bool,
}

impl State {
    pub(crate) const fn new(rounds: usize, counter: Counter) -> Self {
        Self {
            rounds,
            words: [0; STATE_WORDS],
            key_stream: [0; BLOCK_BYTES],
            index: 0,
            limit_word0: 0,
            limit_word1: 0,
            limit_word2: 0,
            counter,
            counter_exhausted: false,
            initialised: false,
        }
    }

    pub(crate) fn init_original(&mut self, key: &[u8], iv: &[u8]) {
        self.words.fill(0);
        set_key(&mut self.words, key);
        for (index, bytes) in iv.as_chunks::<4>().0.iter().enumerate() {
            self.words[14 + index] = u32::from_le_bytes(*bytes);
        }
        self.counter = Counter::Original;
        self.reset();
        self.initialised = true;
    }

    pub(crate) fn init_ietf(&mut self, key: &[u8], iv: &[u8]) {
        self.words.fill(0);
        set_key(&mut self.words, key);
        for (index, bytes) in iv.as_chunks::<4>().0.iter().enumerate() {
            self.words[13 + index] = u32::from_le_bytes(*bytes);
        }
        self.counter = Counter::Ietf;
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
        Ok(input ^ self.next_byte()?)
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
            *output = *input ^ self.next_byte()?;
        }
        Ok(input.len())
    }

    pub(crate) fn reset(&mut self) {
        self.index = 0;
        self.limit_word0 = 0;
        self.limit_word1 = 0;
        self.limit_word2 = 0;
        self.counter_exhausted = false;
        self.words[12] = 0;
        if matches!(self.counter, Counter::Original) {
            self.words[13] = 0;
        }
    }

    fn next_byte(&mut self) -> Result<u8, StreamError> {
        if self.index == 0 {
            if self.counter_exhausted {
                return Err(StreamError::CounterExhausted);
            }
            self.key_stream = block(self.rounds, &self.words);
            self.advance_counter()?;
        }
        let output = self.key_stream[self.index];
        self.index = (self.index + 1) & (BLOCK_BYTES - 1);
        Ok(output)
    }

    fn advance_counter(&mut self) -> Result<(), StreamError> {
        match self.counter {
            Counter::Original => {
                self.words[12] = self.words[12].wrapping_add(1);
                if self.words[12] == 0 {
                    self.words[13] = self.words[13].wrapping_add(1);
                }
                Ok(())
            }
            Counter::Ietf => {
                if self.words[12] == u32::MAX {
                    self.counter_exhausted = true;
                } else {
                    self.words[12] += 1;
                }
                Ok(())
            }
        }
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

pub(crate) fn set_key(state: &mut [u32; STATE_WORDS], key: &[u8]) {
    state[..4].copy_from_slice(if key.len() == 16 { &TAU } else { &SIGMA });

    for (index, bytes) in key[..16].as_chunks::<4>().0.iter().enumerate() {
        state[4 + index] = u32::from_le_bytes(*bytes);
    }
    for (index, bytes) in key[key.len() - 16..].as_chunks::<4>().0.iter().enumerate() {
        state[8 + index] = u32::from_le_bytes(*bytes);
    }
}

pub(crate) fn block(rounds: usize, input: &[u32; STATE_WORDS]) -> [u8; BLOCK_BYTES] {
    let mut words = permutation(rounds, input);
    for (word, original) in words.iter_mut().zip(input) {
        *word = word.wrapping_add(*original);
    }

    let mut output = [0u8; BLOCK_BYTES];
    for (bytes, word) in output.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *bytes = word.to_le_bytes();
    }
    output
}

pub(crate) fn permutation(rounds: usize, input: &[u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut state = *input;
    for _ in (0..rounds).step_by(2) {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);

        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
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

    a = a.wrapping_add(b);
    d = (d ^ a).rotate_left(16);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_left(12);
    a = a.wrapping_add(b);
    d = (d ^ a).rotate_left(8);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_left(7);

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
        let mut state = State::new(20, Counter::Original);
        state.limit_word0 = u32::MAX;
        state.limit_word1 = u32::MAX;
        state.limit_word2 = 0x1f;
        assert!(state.limit_exceeded_by(1));
    }

    #[test]
    fn ietf_counter_wrap_is_rejected() {
        let mut state = State::new(20, Counter::Ietf);
        state.init_ietf(&[0; 32], &[0; 12]);
        state.words[12] = u32::MAX;
        assert_eq!(
            state.process_bytes(&[0; BLOCK_BYTES], &mut [0; BLOCK_BYTES]),
            Ok(BLOCK_BYTES)
        );
        assert_eq!(
            state.process_bytes(&[0], &mut [0]),
            Err(StreamError::CounterExhausted)
        );
    }
}
