//! HC-256 stream cipher, ported from Bouncy Castle's `HC256Engine`.
//!
//! The canonical HC-256 construction uses a 256-bit key and a 256-bit IV.
//! For compatibility with the current Bouncy Castle API, this implementation
//! also accepts a 128-bit key and IVs of at least 128 bits.

use tc_crypto_core::StreamCipher;

/// Canonical HC-256 key size in bytes.
pub const HC256_KEY_BYTES: usize = 32;

/// Alternate 128-bit key size accepted by the Bouncy Castle-compatible API.
pub const HC256_MIN_KEY_BYTES: usize = 16;

/// Minimum IV size accepted by the Bouncy Castle-compatible API.
pub const HC256_MIN_IV_BYTES: usize = 16;

/// Number of IV bytes used to initialize HC-256.
pub const HC256_IV_BYTES: usize = 32;

const TABLE_WORDS: usize = 1024;
const COUNTER_MASK: usize = 2047;

/// Validated and normalized HC-256 key and IV parameters.
///
/// A 16-byte key is repeated to form the 32-byte internal key. An IV from 16
/// through 31 bytes is extended by repeating its leading bytes, while an IV
/// longer than 32 bytes is truncated. These rules match BC `HC256Engine`.
pub struct Hc256Params {
    key: [u8; HC256_KEY_BYTES],
    iv: [u8; HC256_IV_BYTES],
}

impl Hc256Params {
    /// Validates and copies a 16- or 32-byte key and an IV of at least 16 bytes.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, Hc256Error> {
        if key.len() != HC256_MIN_KEY_BYTES && key.len() != HC256_KEY_BYTES {
            return Err(Hc256Error::InvalidKeyLength(key.len()));
        }
        if iv.len() < HC256_MIN_IV_BYTES {
            return Err(Hc256Error::InvalidIvLength(iv.len()));
        }

        let mut owned_key = [0u8; HC256_KEY_BYTES];
        if key.len() == HC256_MIN_KEY_BYTES {
            owned_key[..HC256_MIN_KEY_BYTES].copy_from_slice(key);
            owned_key[HC256_MIN_KEY_BYTES..].copy_from_slice(key);
        } else {
            owned_key.copy_from_slice(key);
        }

        let mut owned_iv = [0u8; HC256_IV_BYTES];
        let copied = core::cmp::min(iv.len(), HC256_IV_BYTES);
        owned_iv[..copied].copy_from_slice(&iv[..copied]);
        if copied < HC256_IV_BYTES {
            let remaining = HC256_IV_BYTES - copied;
            owned_iv[copied..].copy_from_slice(&iv[..remaining]);
        }

        Ok(Self {
            key: owned_key,
            iv: owned_iv,
        })
    }
}

impl core::fmt::Debug for Hc256Params {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Hc256Params")
            .field("normalized_key_len", &HC256_KEY_BYTES)
            .field("normalized_iv_len", &HC256_IV_BYTES)
            .finish()
    }
}

/// Errors returned by HC-256 parameter validation and processing.
#[derive(Debug, PartialEq, Eq)]
pub enum Hc256Error {
    /// The key is neither 16 nor 32 bytes.
    InvalidKeyLength(usize),
    /// The IV is shorter than 16 bytes.
    InvalidIvLength(usize),
    /// A data method was called before initialization.
    NotInitialised,
    /// The output buffer is shorter than the input.
    OutputBufferTooShort,
}

impl core::fmt::Display for Hc256Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKeyLength(actual) => {
                write!(f, "HC-256 key length {actual} is neither 16 nor 32 bytes")
            }
            Self::InvalidIvLength(actual) => {
                write!(f, "HC-256 IV length {actual} is shorter than 16 bytes")
            }
            Self::NotInitialised => f.write_str("HC-256 engine not initialised"),
            Self::OutputBufferTooShort => f.write_str("output buffer shorter than input"),
        }
    }
}

impl core::error::Error for Hc256Error {}

/// The HC-256 stream cipher engine (BC `HC256Engine`).
pub struct Hc256Engine {
    p: [u32; TABLE_WORDS],
    q: [u32; TABLE_WORDS],
    counter: usize,
    key: [u8; HC256_KEY_BYTES],
    iv: [u8; HC256_IV_BYTES],
    word: [u8; 4],
    word_index: usize,
    initialised: bool,
}

impl Hc256Engine {
    /// Creates an uninitialized HC-256 engine.
    pub fn new() -> Self {
        Self {
            p: [0u32; TABLE_WORDS],
            q: [0u32; TABLE_WORDS],
            counter: 0,
            key: [0u8; HC256_KEY_BYTES],
            iv: [0u8; HC256_IV_BYTES],
            word: [0u8; 4],
            word_index: 0,
            initialised: false,
        }
    }

    #[inline]
    fn step(&mut self) -> u32 {
        let j = self.counter & 1023;
        let j3 = j.wrapping_sub(3) & 1023;
        let j10 = j.wrapping_sub(10) & 1023;
        let j12 = j.wrapping_sub(12) & 1023;
        let j1023 = j.wrapping_sub(1023) & 1023;

        let result = if self.counter < 1024 {
            let x = self.p[j3];
            let y = self.p[j1023];
            let cross = self.q[((x ^ y) & 1023) as usize];
            self.p[j] = self.p[j]
                .wrapping_add(self.p[j10])
                .wrapping_add(x.rotate_right(10) ^ y.rotate_right(23))
                .wrapping_add(cross);

            let x = self.p[j12];
            let h = self.q[(x & 0xff) as usize]
                .wrapping_add(self.q[256 + ((x >> 8) & 0xff) as usize])
                .wrapping_add(self.q[512 + ((x >> 16) & 0xff) as usize])
                .wrapping_add(self.q[768 + ((x >> 24) & 0xff) as usize]);
            h ^ self.p[j]
        } else {
            let x = self.q[j3];
            let y = self.q[j1023];
            let cross = self.p[((x ^ y) & 1023) as usize];
            self.q[j] = self.q[j]
                .wrapping_add(self.q[j10])
                .wrapping_add(x.rotate_right(10) ^ y.rotate_right(23))
                .wrapping_add(cross);

            let x = self.q[j12];
            let h = self.p[(x & 0xff) as usize]
                .wrapping_add(self.p[256 + ((x >> 8) & 0xff) as usize])
                .wrapping_add(self.p[512 + ((x >> 16) & 0xff) as usize])
                .wrapping_add(self.p[768 + ((x >> 24) & 0xff) as usize]);
            h ^ self.q[j]
        };

        self.counter = (self.counter + 1) & COUNTER_MASK;
        result
    }

    fn initialize_state(&mut self) {
        self.counter = 0;
        self.word_index = 0;
        self.word = [0u8; 4];

        let mut w = [0u32; 2560];
        for (i, chunk) in self.key.chunks_exact(4).enumerate() {
            w[i] = u32::from_le_bytes(chunk.try_into().expect("four-byte key chunk"));
        }
        for (i, chunk) in self.iv.chunks_exact(4).enumerate() {
            w[8 + i] = u32::from_le_bytes(chunk.try_into().expect("four-byte IV chunk"));
        }

        for i in 16..w.len() {
            let x = w[i - 2];
            let y = w[i - 15];
            w[i] = (x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10))
                .wrapping_add(w[i - 7])
                .wrapping_add(y.rotate_right(7) ^ y.rotate_right(18) ^ (y >> 3))
                .wrapping_add(w[i - 16])
                .wrapping_add(i as u32);
        }

        self.p.copy_from_slice(&w[512..1536]);
        self.q.copy_from_slice(&w[1536..2560]);

        for _ in 0..4096 {
            self.step();
        }
        self.counter = 0;
    }

    #[inline]
    fn next_byte(&mut self) -> u8 {
        if self.word_index == 0 {
            self.word = self.step().to_le_bytes();
        }
        let result = self.word[self.word_index];
        self.word_index = (self.word_index + 1) & 3;
        result
    }
}

impl Default for Hc256Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCipher for Hc256Engine {
    type Params<'a> = Hc256Params;
    type Error = Hc256Error;

    fn algorithm_name(&self) -> &str {
        "HC-256"
    }

    fn init(
        &mut self,
        _for_encryption: bool,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.key.copy_from_slice(&params.key);
        self.iv.copy_from_slice(&params.iv);
        self.initialize_state();
        self.initialised = true;
        Ok(())
    }

    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
        if !self.initialised {
            return Err(Hc256Error::NotInitialised);
        }
        Ok(input ^ self.next_byte())
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(Hc256Error::NotInitialised);
        }
        if output.len() < input.len() {
            return Err(Hc256Error::OutputBufferTooShort);
        }

        for (source, destination) in input.iter().zip(output.iter_mut()) {
            *destination = *source ^ self.next_byte();
        }
        Ok(input.len())
    }

    fn reset(&mut self) {
        if self.initialised {
            self.initialize_state();
        }
    }
}
