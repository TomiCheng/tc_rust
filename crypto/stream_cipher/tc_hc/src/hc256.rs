//! HC-256 stream cipher.

use ::core::fmt;

use tc_cipher::{CipherDirection, InitError, StreamCipher, StreamCipherInit, StreamError};
use tc_crypto::AlgorithmName;
use tc_params::KeyWithIvParams;

/// Canonical HC-256 key length in bytes.
pub const KEY_BYTES: usize = 32;
/// Alternate key length accepted for Bouncy Castle compatibility.
pub const MIN_KEY_BYTES: usize = 16;
/// Internal HC-256 IV length in bytes.
pub const IV_BYTES: usize = 32;
/// Minimum accepted HC-256 IV length in bytes.
pub const MIN_IV_BYTES: usize = 16;

const TABLE_WORDS: usize = 1024;
const COUNTER_MASK: usize = 2047;

/// HC-256 stream cipher engine.
pub struct Hc256Engine {
    p: [u32; TABLE_WORDS],
    q: [u32; TABLE_WORDS],
    counter: usize,
    key: [u8; KEY_BYTES],
    iv: [u8; IV_BYTES],
    word: [u8; 4],
    word_index: usize,
    initialised: bool,
}

impl Hc256Engine {
    /// Creates an uninitialised HC-256 engine.
    pub const fn new() -> Self {
        Self {
            p: [0; TABLE_WORDS],
            q: [0; TABLE_WORDS],
            counter: 0,
            key: [0; KEY_BYTES],
            iv: [0; IV_BYTES],
            word: [0; 4],
            word_index: 0,
            initialised: false,
        }
    }

    #[inline]
    fn step(&mut self) -> u32 {
        let index = self.counter & 1023;
        let index3 = index.wrapping_sub(3) & 1023;
        let index10 = index.wrapping_sub(10) & 1023;
        let index12 = index.wrapping_sub(12) & 1023;
        let index1023 = index.wrapping_sub(1023) & 1023;
        let result = if self.counter < 1024 {
            let x = self.p[index3];
            let y = self.p[index1023];
            let cross = self.q[((x ^ y) & 1023) as usize];
            self.p[index] = self.p[index]
                .wrapping_add(self.p[index10])
                .wrapping_add(x.rotate_right(10) ^ y.rotate_right(23))
                .wrapping_add(cross);
            let x = self.p[index12];
            let h = self.q[(x & 0xff) as usize]
                .wrapping_add(self.q[256 + ((x >> 8) & 0xff) as usize])
                .wrapping_add(self.q[512 + ((x >> 16) & 0xff) as usize])
                .wrapping_add(self.q[768 + ((x >> 24) & 0xff) as usize]);
            h ^ self.p[index]
        } else {
            let x = self.q[index3];
            let y = self.q[index1023];
            let cross = self.p[((x ^ y) & 1023) as usize];
            self.q[index] = self.q[index]
                .wrapping_add(self.q[index10])
                .wrapping_add(x.rotate_right(10) ^ y.rotate_right(23))
                .wrapping_add(cross);
            let x = self.q[index12];
            let h = self.p[(x & 0xff) as usize]
                .wrapping_add(self.p[256 + ((x >> 8) & 0xff) as usize])
                .wrapping_add(self.p[512 + ((x >> 16) & 0xff) as usize])
                .wrapping_add(self.p[768 + ((x >> 24) & 0xff) as usize]);
            h ^ self.q[index]
        };
        self.counter = (self.counter + 1) & COUNTER_MASK;
        result
    }

    fn initialize_state(&mut self) {
        self.counter = 0;
        self.word_index = 0;
        self.word = [0; 4];

        let mut words = [0u32; 2560];
        for (index, bytes) in self.key.chunks_exact(4).enumerate() {
            words[index] = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        for (index, bytes) in self.iv.chunks_exact(4).enumerate() {
            words[8 + index] = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        for index in 16..words.len() {
            let x = words[index - 2];
            let y = words[index - 15];
            words[index] = (x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10))
                .wrapping_add(words[index - 7])
                .wrapping_add(y.rotate_right(7) ^ y.rotate_right(18) ^ (y >> 3))
                .wrapping_add(words[index - 16])
                .wrapping_add(index as u32);
        }
        self.p.copy_from_slice(&words[512..1536]);
        self.q.copy_from_slice(&words[1536..2560]);
        words.fill(0);
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

impl AlgorithmName for Hc256Engine {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("HC-256")
    }
}

impl StreamCipher for Hc256Engine {
    type Error = StreamError;

    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        Ok(input ^ self.next_byte())
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        if output.len() < input.len() {
            return Err(StreamError::BufferTooShort);
        }
        for (input, output) in input.iter().zip(output.iter_mut()) {
            *output = *input ^ self.next_byte();
        }
        Ok(input.len())
    }

    fn reset(&mut self) {
        if self.initialised {
            self.initialize_state();
        }
    }
}

impl StreamCipherInit for Hc256Engine {
    type Params<'a> = dyn KeyWithIvParams + 'a;
    type Error = InitError;

    fn init(
        &mut self,
        _direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), <Self as StreamCipherInit>::Error> {
        let key = params.key();
        if key.len() != MIN_KEY_BYTES && key.len() != KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if iv.len() < MIN_IV_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }

        if key.len() == MIN_KEY_BYTES {
            self.key[..MIN_KEY_BYTES].copy_from_slice(key);
            self.key[MIN_KEY_BYTES..].copy_from_slice(key);
        } else {
            self.key.copy_from_slice(key);
        }
        let copied = iv.len().min(IV_BYTES);
        self.iv[..copied].copy_from_slice(&iv[..copied]);
        if copied < IV_BYTES {
            let remaining = IV_BYTES - copied;
            self.iv[copied..].copy_from_slice(&iv[..remaining]);
        }
        self.initialize_state();
        self.initialised = true;
        Ok(())
    }
}
