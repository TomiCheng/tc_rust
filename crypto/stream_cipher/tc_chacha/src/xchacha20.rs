//! XChaCha20 with a 192-bit IV.

use ::core::fmt;

use tc_cipher::{CipherDirection, InitError, StreamCipher, StreamCipherInit, StreamError};
use tc_crypto::AlgorithmName;
use tc_params::{IvParams, KeyParams};

use crate::DEFAULT_ROUNDS;
use crate::chacha::{self, Counter, STATE_WORDS, State};

/// XChaCha20 key length in bytes.
pub const KEY_BYTES: usize = 32;
/// XChaCha20 IV length in bytes.
pub const IV_BYTES: usize = 24;

/// Extended-IV ChaCha20 stream cipher.
pub struct XChaCha20Engine {
    state: State,
}

impl XChaCha20Engine {
    /// Creates an uninitialised XChaCha20 engine.
    pub const fn new() -> Self {
        Self {
            state: State::new(DEFAULT_ROUNDS, Counter::Ietf),
        }
    }
}

impl Default for XChaCha20Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for XChaCha20Engine {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("XChaCha20")
    }
}

impl StreamCipher for XChaCha20Engine {
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

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for XChaCha20Engine {
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

        let mut subkey = hchacha20(key, &iv[..16]);
        let mut ietf_iv = [0u8; crate::chacha7539::IV_BYTES];
        ietf_iv[4..].copy_from_slice(&iv[16..]);
        self.state.init_ietf(&subkey, &ietf_iv);
        subkey.fill(0);
        Ok(())
    }
}

fn hchacha20(key: &[u8], iv: &[u8]) -> [u8; KEY_BYTES] {
    let mut input = [0u32; STATE_WORDS];
    chacha::set_key(&mut input, key);
    for (index, bytes) in iv.as_chunks::<4>().0.iter().enumerate() {
        input[12 + index] = u32::from_le_bytes(*bytes);
    }

    let mut words = chacha::permutation(DEFAULT_ROUNDS, &input);
    let mut subkey = [0u8; KEY_BYTES];
    for (bytes, word) in subkey[..16]
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(&words[..4])
    {
        *bytes = word.to_le_bytes();
    }
    for (bytes, word) in subkey[16..]
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(&words[12..])
    {
        *bytes = word.to_le_bytes();
    }
    input.fill(0);
    words.fill(0);
    subkey
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hchacha20_matches_draft_vector() {
        let key: [u8; KEY_BYTES] = ::core::array::from_fn(|index| index as u8);
        let iv = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41,
            0x59, 0x27,
        ];
        assert_eq!(
            hchacha20(&key, &iv),
            [
                0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87,
                0x7d, 0x73, 0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13,
                0x26, 0xd3, 0xec, 0xdc,
            ]
        );
    }
}
