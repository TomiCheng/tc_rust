//! IETF ChaCha20 with a 32-bit counter and 96-bit IV.

use ::core::fmt;

use tc_cipher::{CipherDirection, InitError, StreamCipher, StreamCipherInit, StreamError};
use tc_crypto::AlgorithmName;
use tc_params::{IvParams, KeyParams};

use crate::DEFAULT_ROUNDS;
use crate::chacha::{Counter, State};

/// ChaCha7539 key length in bytes.
pub const KEY_BYTES: usize = 32;
/// ChaCha7539 IV length in bytes.
pub const IV_BYTES: usize = 12;

/// IETF ChaCha20 stream cipher.
pub struct ChaCha7539Engine {
    state: State,
}

impl ChaCha7539Engine {
    /// Creates an uninitialised ChaCha7539 engine.
    pub const fn new() -> Self {
        Self {
            state: State::new(DEFAULT_ROUNDS, Counter::Ietf),
        }
    }
}

impl Default for ChaCha7539Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for ChaCha7539Engine {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("ChaCha7539")
    }
}

impl StreamCipher for ChaCha7539Engine {
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

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for ChaCha7539Engine {
    type Error = InitError;

    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        let key = params.key();
        if key.len() != KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }

        let iv = params.iv();
        if iv.len() != IV_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }

        self.state.init_ietf(key, iv);
        Ok(())
    }
}
