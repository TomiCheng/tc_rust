//! XSalsa20 with a 192-bit IV.

use ::core::fmt;

use tc_cipher::{CipherDirection, InitError, StreamCipher, StreamCipherInit, StreamError};
use tc_crypto::AlgorithmName;
use tc_params::KeyWithIvParams;

use crate::DEFAULT_ROUNDS;
use crate::salsa::{self, State};

/// XSalsa20 key length in bytes.
pub const KEY_BYTES: usize = 32;
/// XSalsa20 IV length in bytes.
pub const IV_BYTES: usize = 24;

/// Extended-IV Salsa20 stream cipher.
pub struct Xsalsa20Engine {
    state: State,
}

impl Xsalsa20Engine {
    /// Creates an uninitialised XSalsa20 engine.
    pub const fn new() -> Self {
        Self {
            state: State::new(DEFAULT_ROUNDS),
        }
    }
}

impl Default for Xsalsa20Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for Xsalsa20Engine {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("XSalsa20")
    }
}

impl StreamCipher for Xsalsa20Engine {
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

impl StreamCipherInit for Xsalsa20Engine {
    type Params<'a> = dyn KeyWithIvParams + 'a;
    type Error = InitError;

    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), <Self as StreamCipherInit>::Error> {
        let key = params.key();
        if key.len() != KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if iv.len() != IV_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }

        self.state.words.fill(0);
        salsa::set_key(&mut self.state.words, key, iv);
        self.state.words[8] = u32::from_le_bytes(iv[8..12].try_into().unwrap());
        self.state.words[9] = u32::from_le_bytes(iv[12..16].try_into().unwrap());

        let mut output = salsa::block(DEFAULT_ROUNDS, &self.state.words);
        self.state.words[1] = output[0].wrapping_sub(self.state.words[0]);
        self.state.words[2] = output[5].wrapping_sub(self.state.words[5]);
        self.state.words[3] = output[10].wrapping_sub(self.state.words[10]);
        self.state.words[4] = output[15].wrapping_sub(self.state.words[15]);
        self.state.words[11] = output[6].wrapping_sub(self.state.words[6]);
        self.state.words[12] = output[7].wrapping_sub(self.state.words[7]);
        self.state.words[13] = output[8].wrapping_sub(self.state.words[8]);
        self.state.words[14] = output[9].wrapping_sub(self.state.words[9]);
        output.fill(0);

        self.state.words[6] = u32::from_le_bytes(iv[16..20].try_into().unwrap());
        self.state.words[7] = u32::from_le_bytes(iv[20..24].try_into().unwrap());
        self.state.finish_initialization();
        Ok(())
    }
}
