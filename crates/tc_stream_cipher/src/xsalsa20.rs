//! XSalsa20 stream cipher, ported from Bouncy Castle's `XSalsa20Engine`.
//!
//! XSalsa20 uses HSalsa20 to derive a subkey from a 256-bit key and the first
//! 128 bits of a 192-bit nonce, then runs Salsa20 with the remaining 64 bits.

use tc_cipher_core::{StreamCipher, StreamCipherInit};

use crate::{
    StreamCipherError,
    salsa20::{SALSA20_DEFAULT_ROUNDS, Salsa20Core, salsa_core, set_salsa_key},
};

/// XSalsa20 key size in bytes.
pub const XSALSA20_KEY_BYTES: usize = 32;

/// XSalsa20 nonce size in bytes.
pub const XSALSA20_NONCE_BYTES: usize = 24;

/// Validated XSalsa20 key and nonce parameters.
pub struct Xsalsa20Params {
    key: [u8; XSALSA20_KEY_BYTES],
    nonce: [u8; XSALSA20_NONCE_BYTES],
}

impl Xsalsa20Params {
    /// Validates and copies a 32-byte key and 24-byte nonce.
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, StreamCipherError> {
        if key.len() != XSALSA20_KEY_BYTES {
            return Err(StreamCipherError::InvalidKeyLength(key.len()));
        }
        if nonce.len() != XSALSA20_NONCE_BYTES {
            return Err(StreamCipherError::InvalidNonceLength {
                expected: XSALSA20_NONCE_BYTES,
                actual: nonce.len(),
            });
        }

        let mut owned_key = [0u8; XSALSA20_KEY_BYTES];
        owned_key.copy_from_slice(key);
        let mut owned_nonce = [0u8; XSALSA20_NONCE_BYTES];
        owned_nonce.copy_from_slice(nonce);
        Ok(Self {
            key: owned_key,
            nonce: owned_nonce,
        })
    }
}

impl core::fmt::Debug for Xsalsa20Params {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Xsalsa20Params")
            .field("key_len", &XSALSA20_KEY_BYTES)
            .field("nonce_len", &XSALSA20_NONCE_BYTES)
            .finish()
    }
}

/// The XSalsa20 stream cipher engine (BC `XSalsa20Engine`).
pub struct Xsalsa20Engine {
    core: Salsa20Core,
}

impl Xsalsa20Engine {
    /// Creates an uninitialized 20-round XSalsa20 engine.
    pub fn new() -> Self {
        Self {
            core: Salsa20Core::new(SALSA20_DEFAULT_ROUNDS),
        }
    }

    fn initialize(&mut self, params: &Xsalsa20Params) {
        self.core.state.fill(0);
        set_salsa_key(&mut self.core.state, &params.key, &params.nonce);

        self.core.state[8] = u32::from_le_bytes(
            params.nonce[8..12]
                .try_into()
                .expect("four-byte nonce chunk"),
        );
        self.core.state[9] = u32::from_le_bytes(
            params.nonce[12..16]
                .try_into()
                .expect("four-byte nonce chunk"),
        );

        let hsalsa_output = salsa_core(SALSA20_DEFAULT_ROUNDS, &self.core.state);
        self.core.state[1] = hsalsa_output[0].wrapping_sub(self.core.state[0]);
        self.core.state[2] = hsalsa_output[5].wrapping_sub(self.core.state[5]);
        self.core.state[3] = hsalsa_output[10].wrapping_sub(self.core.state[10]);
        self.core.state[4] = hsalsa_output[15].wrapping_sub(self.core.state[15]);
        self.core.state[11] = hsalsa_output[6].wrapping_sub(self.core.state[6]);
        self.core.state[12] = hsalsa_output[7].wrapping_sub(self.core.state[7]);
        self.core.state[13] = hsalsa_output[8].wrapping_sub(self.core.state[8]);
        self.core.state[14] = hsalsa_output[9].wrapping_sub(self.core.state[9]);

        self.core.state[6] = u32::from_le_bytes(
            params.nonce[16..20]
                .try_into()
                .expect("four-byte nonce chunk"),
        );
        self.core.state[7] = u32::from_le_bytes(
            params.nonce[20..24]
                .try_into()
                .expect("four-byte nonce chunk"),
        );
        self.core.finish_initialization();
    }
}

impl Default for Xsalsa20Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCipher for Xsalsa20Engine {
    type Error = StreamCipherError;

    fn algorithm_name(&self) -> &str {
        "XSalsa20"
    }

    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
        self.core.return_byte(input)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.process_bytes(input, output)
    }

    fn reset(&mut self) {
        self.core.reset();
    }
}

impl StreamCipherInit for Xsalsa20Engine {
    type Params<'a> = Xsalsa20Params;

    fn init(&mut self, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.initialize(params);
        Ok(())
    }
}
