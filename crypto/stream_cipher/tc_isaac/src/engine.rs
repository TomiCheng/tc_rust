//! ISAAC engine.

use ::core::fmt;

use tc_cipher::{CipherDirection, InitError, StreamCipher, StreamCipherInit, StreamError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::MAX_KEY_BYTES;

const MIX_WORDS: usize = 8;
const STATE_WORDS: usize = 256;
const KEYSTREAM_BYTES: usize = STATE_WORDS * 4;

/// ISAAC stream cipher engine.
pub struct IsaacEngine {
    state: [u32; STATE_WORDS],
    a: u32,
    b: u32,
    c: u32,
    key_stream: [u8; KEYSTREAM_BYTES],
    key_stream_pos: usize,
    working_key: [u8; MAX_KEY_BYTES],
    key_len: usize,
    initialised: bool,
}

impl IsaacEngine {
    /// Creates an uninitialised ISAAC engine.
    pub const fn new() -> Self {
        Self {
            state: [0; STATE_WORDS],
            a: 0,
            b: 0,
            c: 0,
            key_stream: [0; KEYSTREAM_BYTES],
            key_stream_pos: 0,
            working_key: [0; MAX_KEY_BYTES],
            key_len: 0,
            initialised: false,
        }
    }

    fn generate_key_stream(&mut self) {
        let mut a = self.a;
        self.c = self.c.wrapping_add(1);
        let mut b = self.b.wrapping_add(self.c);
        for index in 0..STATE_WORDS {
            let x = self.state[index];
            match index & 3 {
                0 => a ^= a << 13,
                1 => a ^= a >> 6,
                2 => a ^= a << 2,
                _ => a ^= a >> 16,
            }
            a = a.wrapping_add(self.state[index ^ 0x80]);
            let y = self.state[((x >> 2) & 0xff) as usize]
                .wrapping_add(a)
                .wrapping_add(b);
            self.state[index] = y;
            b = self.state[((y >> 10) & 0xff) as usize].wrapping_add(x);
            self.key_stream[index * 4..index * 4 + 4].copy_from_slice(&b.to_be_bytes());
        }
        self.a = a;
        self.b = b;
    }

    fn initialize_state(&mut self) {
        self.state.fill(0);
        self.a = 0;
        self.b = 0;
        self.c = 0;
        self.key_stream.fill(0);
        self.key_stream_pos = 0;

        let key = &self.working_key[..self.key_len];
        let mut chunks = key.chunks_exact(4);
        for (destination, bytes) in self.state.iter_mut().zip(chunks.by_ref()) {
            *destination = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut word = [0; 4];
            word[..remainder.len()].copy_from_slice(remainder);
            self.state[self.key_len / 4] = u32::from_le_bytes(word);
        }

        let mut mix_state = [0x9e37_79b9; MIX_WORDS];
        for _ in 0..4 {
            Self::mix(&mut mix_state);
        }
        for _ in 0..2 {
            for offset in (0..STATE_WORDS).step_by(MIX_WORDS) {
                for (mix_word, state_word) in mix_state
                    .iter_mut()
                    .zip(&self.state[offset..offset + MIX_WORDS])
                {
                    *mix_word = mix_word.wrapping_add(*state_word);
                }
                Self::mix(&mut mix_state);
                self.state[offset..offset + MIX_WORDS].copy_from_slice(&mix_state);
            }
        }
        mix_state.fill(0);

        // BC generates once during setup, then again for the first visible block.
        self.generate_key_stream();
    }

    #[allow(clippy::many_single_char_names)]
    fn mix(state: &mut [u32; MIX_WORDS]) {
        let [
            mut x0,
            mut x1,
            mut x2,
            mut x3,
            mut x4,
            mut x5,
            mut x6,
            mut x7,
        ] = *state;
        x0 ^= x1 << 11;
        x3 = x3.wrapping_add(x0);
        x1 = x1.wrapping_add(x2);
        x1 ^= x2 >> 2;
        x4 = x4.wrapping_add(x1);
        x2 = x2.wrapping_add(x3);
        x2 ^= x3 << 8;
        x5 = x5.wrapping_add(x2);
        x3 = x3.wrapping_add(x4);
        x3 ^= x4 >> 16;
        x6 = x6.wrapping_add(x3);
        x4 = x4.wrapping_add(x5);
        x4 ^= x5 << 10;
        x7 = x7.wrapping_add(x4);
        x5 = x5.wrapping_add(x6);
        x5 ^= x6 >> 4;
        x0 = x0.wrapping_add(x5);
        x6 = x6.wrapping_add(x7);
        x6 ^= x7 << 8;
        x1 = x1.wrapping_add(x6);
        x7 = x7.wrapping_add(x0);
        x7 ^= x0 >> 9;
        x2 = x2.wrapping_add(x7);
        x0 = x0.wrapping_add(x1);
        *state = [x0, x1, x2, x3, x4, x5, x6, x7];
    }

    fn next_byte(&mut self) -> u8 {
        if self.key_stream_pos == 0 {
            self.generate_key_stream();
        }
        let result = self.key_stream[self.key_stream_pos];
        self.key_stream_pos = (self.key_stream_pos + 1) & (KEYSTREAM_BYTES - 1);
        result
    }
}

impl Default for IsaacEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for IsaacEngine {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("ISAAC")
    }
}

impl StreamCipher for IsaacEngine {
    type Error = StreamError;

    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        Ok(input ^ self.next_byte())
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        if output.len() < input.len() {
            return Err(StreamError::BufferTooShort);
        }
        let mut position = 0;
        while position < input.len() {
            if self.key_stream_pos == 0 {
                self.generate_key_stream();
            }
            let length = (input.len() - position).min(KEYSTREAM_BYTES - self.key_stream_pos);
            for index in 0..length {
                output[position + index] =
                    input[position + index] ^ self.key_stream[self.key_stream_pos + index];
            }
            position += length;
            self.key_stream_pos = (self.key_stream_pos + length) & (KEYSTREAM_BYTES - 1);
        }
        Ok(input.len())
    }

    fn reset(&mut self) {
        if self.initialised {
            self.initialize_state();
        }
    }
}

impl StreamCipherInit for IsaacEngine {
    type Params<'a> = dyn KeyParams + 'a;
    type Error = InitError;

    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), <Self as StreamCipherInit>::Error> {
        let key = params.key();
        if key.len() > MAX_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        self.working_key.fill(0);
        self.working_key[..key.len()].copy_from_slice(key);
        self.key_len = key.len();
        self.initialize_state();
        self.initialised = true;
        Ok(())
    }
}
