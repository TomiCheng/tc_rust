//! IETF ChaCha20 stream cipher, ported from Bouncy Castle's
//! `ChaCha7539Engine`.
//!
//! This construction uses a 32-bit block counter and a 96-bit nonce.

use tc_crypto_core::StreamCipher;

use crate::{
    StreamCipherError,
    chacha::{CHACHA_DEFAULT_ROUNDS, ChaChaCore},
};

/// ChaCha7539 key size in bytes.
pub const CHACHA7539_KEY_BYTES: usize = 32;

/// ChaCha7539 nonce size in bytes.
pub const CHACHA7539_NONCE_BYTES: usize = 12;

/// Validated ChaCha7539 key and nonce parameters.
pub struct ChaCha7539Params {
    key: [u8; CHACHA7539_KEY_BYTES],
    nonce: [u8; CHACHA7539_NONCE_BYTES],
}

impl ChaCha7539Params {
    /// Validates and copies a 32-byte key and 12-byte nonce.
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, StreamCipherError> {
        if key.len() != CHACHA7539_KEY_BYTES {
            return Err(StreamCipherError::InvalidKeyLength(key.len()));
        }
        if nonce.len() != CHACHA7539_NONCE_BYTES {
            return Err(StreamCipherError::InvalidNonceLength {
                expected: CHACHA7539_NONCE_BYTES,
                actual: nonce.len(),
            });
        }

        let mut owned_key = [0u8; CHACHA7539_KEY_BYTES];
        owned_key.copy_from_slice(key);
        let mut owned_nonce = [0u8; CHACHA7539_NONCE_BYTES];
        owned_nonce.copy_from_slice(nonce);
        Ok(Self {
            key: owned_key,
            nonce: owned_nonce,
        })
    }
}

impl core::fmt::Debug for ChaCha7539Params {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChaCha7539Params")
            .field("key_len", &CHACHA7539_KEY_BYTES)
            .field("nonce_len", &CHACHA7539_NONCE_BYTES)
            .finish()
    }
}

/// IETF ChaCha20 stream cipher engine (BC `ChaCha7539Engine`).
pub struct ChaCha7539Engine {
    core: ChaChaCore,
}

impl ChaCha7539Engine {
    /// Creates an uninitialized 20-round ChaCha7539 engine.
    pub fn new() -> Self {
        Self {
            core: ChaChaCore::new(CHACHA_DEFAULT_ROUNDS),
        }
    }
}

impl Default for ChaCha7539Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCipher for ChaCha7539Engine {
    type Params<'a> = ChaCha7539Params;
    type Error = StreamCipherError;

    fn algorithm_name(&self) -> &str {
        "ChaCha7539"
    }

    fn init(
        &mut self,
        _for_encryption: bool,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.core.init_ietf(&params.key, &params.nonce);
        Ok(())
    }

    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
        self.core.return_byte(input)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.process_bytes(input, output)
    }

    fn reset(&mut self) {
        self.core.reset_ietf();
    }
}
