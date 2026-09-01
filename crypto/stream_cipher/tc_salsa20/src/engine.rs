//! Salsa20 engine.

use ::core::fmt;

use tc_cipher::{CipherDirection, InitError, StreamCipher, StreamCipherInit, StreamError};
use tc_crypto::AlgorithmName;
use tc_params::KeyWithIvParams;

use crate::salsa::State;
use crate::{DEFAULT_ROUNDS, IV_BYTES, KEY_BYTES, MAX_ROUNDS};

/// Salsa20 with a caller-selected positive, even round count.
pub struct Salsa20Engine {
    rounds: usize,
    state: State,
}

impl Salsa20Engine {
    /// Creates a twenty-round Salsa20 engine.
    pub const fn new() -> Self {
        Self::build(DEFAULT_ROUNDS)
    }

    /// Creates a Salsa20 engine with a positive, even round count.
    pub const fn with_rounds(rounds: usize) -> Result<Self, InitError> {
        if rounds == 0 || rounds & 1 != 0 || rounds > MAX_ROUNDS {
            return Err(InitError::InvalidRounds(rounds));
        }
        Ok(Self::build(rounds))
    }

    const fn build(rounds: usize) -> Self {
        Self {
            rounds,
            state: State::new(rounds),
        }
    }
}

impl Default for Salsa20Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for Salsa20Engine {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        if self.rounds == DEFAULT_ROUNDS {
            output.write_str("Salsa20")
        } else {
            write!(output, "Salsa20/{}", self.rounds)
        }
    }
}

impl StreamCipher for Salsa20Engine {
    type Error = StreamError;

    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
        self.state.return_byte(input)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.state.process_bytes(input, output)
    }

    fn reset(&mut self) {
        self.state.reset();
    }
}

impl<P: KeyWithIvParams + ?Sized> StreamCipherInit<P> for Salsa20Engine {
    type Error = InitError;

    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        let key = params.key();
        if !KEY_BYTES.contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if iv.len() != IV_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }
        self.state.init(key, iv);
        Ok(())
    }
}
