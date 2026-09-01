//! RC4 engine.

use tc_cipher::{CipherDirection, InitError, StreamCipher, StreamCipherInit, StreamError};
use tc_crypto::AlgorithmName;
use tc_params::KeyParams;

use crate::MAX_KEY_BYTES;

const STATE_BYTES: usize = 256;

/// RC4 with a variable-length key.
pub struct Rc4Engine {
    state: [u8; STATE_BYTES],
    x: usize,
    y: usize,
    working_key: [u8; MAX_KEY_BYTES],
    key_len: usize,
    initialised: bool,
}

impl Rc4Engine {
    /// Creates an uninitialised RC4 engine.
    pub const fn new() -> Self {
        Self {
            state: [0; STATE_BYTES],
            x: 0,
            y: 0,
            working_key: [0; MAX_KEY_BYTES],
            key_len: 0,
            initialised: false,
        }
    }

    fn set_key(&mut self) {
        self.x = 0;
        self.y = 0;
        for (index, state) in self.state.iter_mut().enumerate() {
            *state = index as u8;
        }

        let mut key_index = 0usize;
        let mut state_index = 0usize;
        for index in 0..STATE_BYTES {
            state_index =
                (state_index + self.working_key[key_index] as usize + self.state[index] as usize)
                    & 0xff;
            self.state.swap(index, state_index);
            key_index = (key_index + 1) % self.key_len;
        }
    }

    fn next_byte(&mut self) -> u8 {
        self.x = (self.x + 1) & 0xff;
        self.y = (self.y + self.state[self.x] as usize) & 0xff;
        self.state.swap(self.x, self.y);
        let index = (self.state[self.x] as usize + self.state[self.y] as usize) & 0xff;
        self.state[index]
    }
}

impl Default for Rc4Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for Rc4Engine {
    fn write_algo_name(&self, output: &mut dyn core::fmt::Write) -> core::fmt::Result {
        output.write_str("RC4")
    }
}

impl StreamCipher for Rc4Engine {
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

        for (input, output) in input.iter().zip(output.iter_mut()) {
            *output = *input ^ self.next_byte();
        }
        Ok(input.len())
    }

    fn reset(&mut self) {
        if self.initialised {
            self.set_key();
        }
    }
}

impl StreamCipherInit for Rc4Engine {
    type Params<'a> = dyn KeyParams + 'a;
    type Error = InitError;

    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), <Self as StreamCipherInit>::Error> {
        let key = params.key();
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        self.working_key.fill(0);
        self.working_key[..key.len()].copy_from_slice(key);
        self.key_len = key.len();
        self.set_key();
        self.initialised = true;
        Ok(())
    }
}
