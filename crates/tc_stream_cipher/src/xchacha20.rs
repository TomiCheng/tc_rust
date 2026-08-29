//! XChaCha20 stream cipher, ported from Bouncy Castle's `XChaCha20Engine`.
//!
//! XChaCha20 uses HChaCha20 to derive a subkey from a 256-bit key and the
//! first 128 bits of a 192-bit nonce. The remaining 64 nonce bits are then
//! used with the IETF ChaCha20 construction.

use tc_crypto_core::StreamCipher;

use crate::{
    StreamCipherError,
    chacha::{CHACHA_DEFAULT_ROUNDS, ChaChaCore, chacha_permutation, set_chacha_key},
};

/// XChaCha20 key size in bytes.
pub const XCHACHA20_KEY_BYTES: usize = 32;

/// XChaCha20 nonce size in bytes.
pub const XCHACHA20_NONCE_BYTES: usize = 24;

/// Validated XChaCha20 key and nonce parameters.
pub struct XChaCha20Params {
    key: [u8; XCHACHA20_KEY_BYTES],
    nonce: [u8; XCHACHA20_NONCE_BYTES],
}

impl XChaCha20Params {
    /// Validates and copies a 32-byte key and 24-byte nonce.
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, StreamCipherError> {
        if key.len() != XCHACHA20_KEY_BYTES {
            return Err(StreamCipherError::InvalidKeyLength(key.len()));
        }
        if nonce.len() != XCHACHA20_NONCE_BYTES {
            return Err(StreamCipherError::InvalidNonceLength {
                expected: XCHACHA20_NONCE_BYTES,
                actual: nonce.len(),
            });
        }

        let mut owned_key = [0u8; XCHACHA20_KEY_BYTES];
        owned_key.copy_from_slice(key);
        let mut owned_nonce = [0u8; XCHACHA20_NONCE_BYTES];
        owned_nonce.copy_from_slice(nonce);
        Ok(Self {
            key: owned_key,
            nonce: owned_nonce,
        })
    }
}

impl core::fmt::Debug for XChaCha20Params {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XChaCha20Params")
            .field("key_len", &XCHACHA20_KEY_BYTES)
            .field("nonce_len", &XCHACHA20_NONCE_BYTES)
            .finish()
    }
}

/// Extended-nonce ChaCha20 stream cipher engine (BC `XChaCha20Engine`).
pub struct XChaCha20Engine {
    core: ChaChaCore,
}

impl XChaCha20Engine {
    /// Creates an uninitialized XChaCha20 engine.
    pub fn new() -> Self {
        Self {
            core: ChaChaCore::new(CHACHA_DEFAULT_ROUNDS),
        }
    }

    fn initialize(&mut self, params: &XChaCha20Params) {
        let mut h_nonce = [0u8; 16];
        h_nonce.copy_from_slice(&params.nonce[..16]);
        let mut subkey = hchacha20(&params.key, &h_nonce);

        let mut ietf_nonce = [0u8; 12];
        ietf_nonce[4..].copy_from_slice(&params.nonce[16..]);
        self.core.init_ietf(&subkey, &ietf_nonce);
        subkey.fill(0);
    }
}

impl Default for XChaCha20Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCipher for XChaCha20Engine {
    type Params<'a> = XChaCha20Params;
    type Error = StreamCipherError;

    fn algorithm_name(&self) -> &str {
        "XChaCha20"
    }

    fn init(
        &mut self,
        _for_encryption: bool,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.initialize(params);
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

fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut state = [0u32; 16];
    set_chacha_key(&mut state, key);
    for (i, chunk) in nonce.chunks_exact(4).enumerate() {
        state[12 + i] = u32::from_le_bytes(chunk.try_into().expect("four-byte nonce chunk"));
    }

    let state = chacha_permutation(CHACHA_DEFAULT_ROUNDS, &state);
    let mut subkey = [0u8; 32];
    for (chunk, word) in subkey[..16].chunks_exact_mut(4).zip(&state[..4]) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    for (chunk, word) in subkey[16..].chunks_exact_mut(4).zip(&state[12..]) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    subkey
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hchacha20_matches_ietf_draft_vector() {
        let key = core::array::from_fn(|i| i as u8);
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41,
            0x59, 0x27,
        ];
        assert_eq!(
            hchacha20(&key, &nonce),
            [
                0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87,
                0x7d, 0x73, 0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13,
                0x26, 0xd3, 0xec, 0xdc,
            ]
        );
    }
}
