//! HC-128 stream cipher, ported from Bouncy Castle's `HC128Engine`.
//!
//! HC-128 uses a 128-bit key and a 128-bit initialization vector. Encryption
//! and decryption are the same XOR-with-keystream operation.

use tc_cipher_core::{StreamCipher, StreamCipherInit};

use crate::StreamCipherError;

/// HC-128 key size in bytes.
pub const HC128_KEY_BYTES: usize = 16;

/// HC-128 initialization-vector size in bytes.
pub const HC128_IV_BYTES: usize = 16;

const TABLE_WORDS: usize = 512;
const COUNTER_MASK: usize = 1023;

/// Validated HC-128 key and IV parameters.
pub struct Hc128Params {
    key: [u8; HC128_KEY_BYTES],
    iv: [u8; HC128_IV_BYTES],
}

impl Hc128Params {
    /// Validates and copies a 16-byte key and 16-byte IV.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, StreamCipherError> {
        if key.len() != HC128_KEY_BYTES {
            return Err(StreamCipherError::InvalidKeyLength(key.len()));
        }
        if iv.len() != HC128_IV_BYTES {
            return Err(StreamCipherError::InvalidIvLength(iv.len()));
        }

        let mut owned_key = [0u8; HC128_KEY_BYTES];
        owned_key.copy_from_slice(key);
        let mut owned_iv = [0u8; HC128_IV_BYTES];
        owned_iv.copy_from_slice(iv);

        Ok(Self {
            key: owned_key,
            iv: owned_iv,
        })
    }
}

impl core::fmt::Debug for Hc128Params {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Hc128Params")
            .field("key_len", &HC128_KEY_BYTES)
            .field("iv_len", &HC128_IV_BYTES)
            .finish()
    }
}

/// The HC-128 stream cipher engine (BC `HC128Engine`).
pub struct Hc128Engine {
    p: [u32; TABLE_WORDS],
    q: [u32; TABLE_WORDS],
    counter: usize,
    key: [u8; HC128_KEY_BYTES],
    iv: [u8; HC128_IV_BYTES],
    word: [u8; 4],
    word_index: usize,
    initialised: bool,
}

impl Hc128Engine {
    /// Creates an uninitialized HC-128 engine.
    pub fn new() -> Self {
        Self {
            p: [0u32; TABLE_WORDS],
            q: [0u32; TABLE_WORDS],
            counter: 0,
            key: [0u8; HC128_KEY_BYTES],
            iv: [0u8; HC128_IV_BYTES],
            word: [0u8; 4],
            word_index: 0,
            initialised: false,
        }
    }

    #[inline]
    fn f1(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline]
    fn f2(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    #[inline]
    fn g1(x: u32, y: u32, z: u32) -> u32 {
        (x.rotate_right(10) ^ z.rotate_right(23)).wrapping_add(y.rotate_right(8))
    }

    #[inline]
    fn g2(x: u32, y: u32, z: u32) -> u32 {
        (x.rotate_left(10) ^ z.rotate_left(23)).wrapping_add(y.rotate_left(8))
    }

    #[inline]
    fn h1(&self, x: u32) -> u32 {
        self.q[(x & 0xff) as usize].wrapping_add(self.q[256 + ((x >> 16) & 0xff) as usize])
    }

    #[inline]
    fn h2(&self, x: u32) -> u32 {
        self.p[(x & 0xff) as usize].wrapping_add(self.p[256 + ((x >> 16) & 0xff) as usize])
    }

    #[inline]
    fn step(&mut self) -> u32 {
        let j = self.counter & 511;
        let j3 = j.wrapping_sub(3) & 511;
        let j10 = j.wrapping_sub(10) & 511;
        let j12 = j.wrapping_sub(12) & 511;
        let j511 = j.wrapping_sub(511) & 511;

        let result = if self.counter < 512 {
            self.p[j] = self.p[j].wrapping_add(Self::g1(self.p[j3], self.p[j10], self.p[j511]));
            self.h1(self.p[j12]) ^ self.p[j]
        } else {
            self.q[j] = self.q[j].wrapping_add(Self::g2(self.q[j3], self.q[j10], self.q[j511]));
            self.h2(self.q[j12]) ^ self.q[j]
        };

        self.counter = (self.counter + 1) & COUNTER_MASK;
        result
    }

    fn initialize_state(&mut self) {
        self.counter = 0;
        self.word_index = 0;
        self.word = [0u8; 4];

        let mut w = [0u32; 1280];
        for (i, chunk) in self.key.chunks_exact(4).enumerate() {
            w[i] = u32::from_le_bytes(chunk.try_into().expect("four-byte key chunk"));
        }
        w.copy_within(0..4, 4);

        for (i, chunk) in self.iv.chunks_exact(4).enumerate() {
            w[8 + i] = u32::from_le_bytes(chunk.try_into().expect("four-byte IV chunk"));
        }
        w.copy_within(8..12, 12);

        for i in 16..w.len() {
            w[i] = Self::f2(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(Self::f1(w[i - 15]))
                .wrapping_add(w[i - 16])
                .wrapping_add(i as u32);
        }

        self.p.copy_from_slice(&w[256..768]);
        self.q.copy_from_slice(&w[768..1280]);

        for i in 0..TABLE_WORDS {
            self.p[i] = self.step();
        }
        for i in 0..TABLE_WORDS {
            self.q[i] = self.step();
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

impl Default for Hc128Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCipher for Hc128Engine {
    type Error = StreamCipherError;

    fn algorithm_name(&self) -> &str {
        "HC-128"
    }

    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
        if !self.initialised {
            return Err(StreamCipherError::NotInitialised);
        }
        Ok(input ^ self.next_byte())
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(StreamCipherError::NotInitialised);
        }
        if output.len() < input.len() {
            return Err(StreamCipherError::OutputBufferTooShort);
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

impl StreamCipherInit for Hc128Engine {
    type Params<'a> = Hc128Params;

    fn init(&mut self, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.key.copy_from_slice(&params.key);
        self.iv.copy_from_slice(&params.iv);
        self.initialize_state();
        self.initialised = true;
        Ok(())
    }
}
