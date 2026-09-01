//! Original ChaCha engine.

use ::core::fmt;

use tc_cipher::{CipherDirection, InitError, StreamCipher, StreamCipherInit, StreamError};
use tc_crypto::AlgorithmName;
use tc_params::KeyWithIvParams;

use crate::chacha::{Counter, State};
use crate::{DEFAULT_ROUNDS, IV_BYTES, KEY_BYTES, MAX_ROUNDS};

/// Original ChaCha with a caller-selected positive, even round count.
pub struct ChaChaEngine {
    rounds: usize,
    state: State,
}

impl ChaChaEngine {
    /// Creates a twenty-round ChaCha engine.
    pub const fn new() -> Self {
        Self::build(DEFAULT_ROUNDS)
    }

    /// Creates a ChaCha engine with a positive, even round count.
    pub const fn with_rounds(rounds: usize) -> Result<Self, InitError> {
        if rounds == 0 || rounds & 1 != 0 || rounds > MAX_ROUNDS {
            return Err(InitError::InvalidRounds(rounds));
        }
        Ok(Self::build(rounds))
    }

    const fn build(rounds: usize) -> Self {
        Self {
            rounds,
            state: State::new(rounds, Counter::Original),
        }
    }
}

impl Default for ChaChaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for ChaChaEngine {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        write!(output, "ChaCha{}", self.rounds)
    }
}

impl StreamCipher for ChaChaEngine {
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

impl StreamCipherInit for ChaChaEngine {
    type Params<'a> = dyn KeyWithIvParams + 'a;
    type Error = InitError;

    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), <Self as StreamCipherInit>::Error> {
        let key = params.key();
        if !KEY_BYTES.contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        let iv = params.iv();
        if iv.len() != IV_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }

        self.state.init_original(key, iv);
        Ok(())
    }
}
