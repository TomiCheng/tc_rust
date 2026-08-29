//! RC4 stream cipher, ported from Bouncy Castle's `RC4Engine`.
//!
//! RC4 is a symmetric stream cipher: encryption and decryption are the same
//! operation (XOR with the keystream), so the `for_encryption` flag is ignored.
//!
//! ```
//! use tc_stream_cipher::{Rc4Engine, Rc4Params};
//! use tc_cipher_core::{StreamCipher, StreamCipherInit};
//!
//! let params = Rc4Params::new(b"Key").unwrap();
//! let mut cipher = Rc4Engine::new();
//! cipher.init(true, &params).unwrap();
//!
//! let mut out = [0u8; 9];
//! cipher.process_bytes(b"Plaintext", &mut out).unwrap();
//! assert_eq!(out, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
//! ```

use tc_cipher_core::{StreamCipher, StreamCipherInit};

use crate::StreamCipherError;

const STATE_LENGTH: usize = 256;

/// Maximum RC4 key length in bytes (the state size; longer keys are redundant).
pub const RC4_MAX_KEY_BYTES: usize = STATE_LENGTH;

/// Validated RC4 key parameter (1–256 bytes), owning a copy of the key.
pub struct Rc4Params {
    key: [u8; STATE_LENGTH],
    key_len: usize,
}

impl Rc4Params {
    /// Validates the key (1–256 bytes) and copies it in.
    pub fn new(key: &[u8]) -> Result<Self, StreamCipherError> {
        if key.is_empty() || key.len() > RC4_MAX_KEY_BYTES {
            return Err(StreamCipherError::InvalidKeyLength(key.len()));
        }
        let mut buf = [0u8; STATE_LENGTH];
        buf[..key.len()].copy_from_slice(key);
        Ok(Self {
            key: buf,
            key_len: key.len(),
        })
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }
}

impl core::fmt::Debug for Rc4Params {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 不外洩金鑰內容，只顯示長度。
        f.debug_struct("Rc4Params")
            .field("key_len", &self.key_len)
            .finish()
    }
}

/// The RC4 stream cipher engine (bc `RC4Engine`).
pub struct Rc4Engine {
    /// The 256-byte permutation state.
    state: [u8; STATE_LENGTH],
    x: usize,
    y: usize,
    /// The key retained for [`reset`](StreamCipher::reset).
    working_key: [u8; STATE_LENGTH],
    key_len: usize,
    initialised: bool,
}

impl Rc4Engine {
    /// Creates an uninitialised RC4 engine; call `init` before processing.
    pub fn new() -> Self {
        Self {
            state: [0u8; STATE_LENGTH],
            x: 0,
            y: 0,
            working_key: [0u8; STATE_LENGTH],
            key_len: 0,
            initialised: false,
        }
    }

    /// Runs the RC4 key-scheduling algorithm (KSA) over `working_key`.
    fn set_key(&mut self) {
        self.x = 0;
        self.y = 0;
        for (i, s) in self.state.iter_mut().enumerate() {
            *s = i as u8;
        }

        let key_len = self.key_len;
        let mut i1 = 0usize;
        let mut i2 = 0usize;
        for i in 0..STATE_LENGTH {
            i2 = (self.working_key[i1] as usize + self.state[i] as usize + i2) & 0xff;
            self.state.swap(i, i2);
            i1 = (i1 + 1) % key_len;
        }
    }
}

impl Default for Rc4Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCipher for Rc4Engine {
    type Error = StreamCipherError;

    fn algorithm_name(&self) -> &str {
        "RC4"
    }

    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
        if !self.initialised {
            return Err(StreamCipherError::NotInitialised);
        }
        self.x = (self.x + 1) & 0xff;
        self.y = (self.state[self.x] as usize + self.y) & 0xff;
        self.state.swap(self.x, self.y);
        let idx = (self.state[self.x] as usize + self.state[self.y] as usize) & 0xff;
        Ok(input ^ self.state[idx])
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(StreamCipherError::NotInitialised);
        }
        if output.len() < input.len() {
            return Err(StreamCipherError::OutputBufferTooShort);
        }
        for (i, &byte) in input.iter().enumerate() {
            self.x = (self.x + 1) & 0xff;
            self.y = (self.state[self.x] as usize + self.y) & 0xff;
            let sx = self.state[self.x];
            let sy = self.state[self.y];
            self.state[self.x] = sy;
            self.state[self.y] = sx;
            let idx = (sx as usize + sy as usize) & 0xff;
            output[i] = byte ^ self.state[idx];
        }
        Ok(input.len())
    }

    fn reset(&mut self) {
        // 回到 init 後的狀態；未 init 則保持未初始化。
        if self.initialised {
            self.set_key();
        }
    }
}

impl StreamCipherInit for Rc4Engine {
    type Params<'a> = Rc4Params;

    fn init(
        &mut self,
        _for_encryption: bool,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        // RC4 對稱，for_encryption 無關（加解密同一操作）。
        self.working_key[..params.key_len].copy_from_slice(params.key());
        self.key_len = params.key_len;
        self.set_key();
        self.initialised = true;
        Ok(())
    }
}
