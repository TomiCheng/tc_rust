//! ISAAC stream cipher, ported from Bouncy Castle's `IsaacEngine`.
//!
//! ISAAC (Indirection, Shift, Accumulate, Add, and Count) produces 1,024-byte
//! keystream blocks from a 256-word state. Encryption and decryption are the
//! same XOR-with-keystream operation.

use tc_crypto_core::StreamCipher;

use crate::StreamCipherError;

const MIX_WORDS: usize = 8;
const STATE_WORDS: usize = 256;
const KEYSTREAM_BYTES: usize = STATE_WORDS * 4;

/// Maximum key size accepted by BC `IsaacEngine`'s 256-word key state.
pub const ISAAC_MAX_KEY_BYTES: usize = KEYSTREAM_BYTES;

/// Validated ISAAC key parameter, owning up to 1,024 bytes of key material.
///
/// An empty key is accepted for compatibility with BC, whose key-loading code
/// permits every length from zero through the full 256-word state.
pub struct IsaacParams {
    key: [u8; ISAAC_MAX_KEY_BYTES],
    key_len: usize,
}

impl IsaacParams {
    /// Validates and copies a key of at most 1,024 bytes.
    pub fn new(key: &[u8]) -> Result<Self, StreamCipherError> {
        if key.len() > ISAAC_MAX_KEY_BYTES {
            return Err(StreamCipherError::InvalidKeyLength(key.len()));
        }

        let mut owned_key = [0u8; ISAAC_MAX_KEY_BYTES];
        owned_key[..key.len()].copy_from_slice(key);
        Ok(Self {
            key: owned_key,
            key_len: key.len(),
        })
    }

    fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }
}

impl core::fmt::Debug for IsaacParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IsaacParams")
            .field("key_len", &self.key_len)
            .finish()
    }
}

/// The ISAAC stream cipher engine (BC `IsaacEngine`).
pub struct IsaacEngine {
    state: [u32; STATE_WORDS],
    a: u32,
    b: u32,
    c: u32,
    key_stream: [u8; KEYSTREAM_BYTES],
    key_stream_pos: usize,
    working_key: [u8; ISAAC_MAX_KEY_BYTES],
    key_len: usize,
    initialised: bool,
}

impl IsaacEngine {
    /// Creates an uninitialized ISAAC engine.
    pub fn new() -> Self {
        Self {
            state: [0u32; STATE_WORDS],
            a: 0,
            b: 0,
            c: 0,
            key_stream: [0u8; KEYSTREAM_BYTES],
            key_stream_pos: 0,
            working_key: [0u8; ISAAC_MAX_KEY_BYTES],
            key_len: 0,
            initialised: false,
        }
    }

    fn generate_key_stream(&mut self) {
        let mut a = self.a;
        self.c = self.c.wrapping_add(1);
        let mut b = self.b.wrapping_add(self.c);

        for i in 0..STATE_WORDS {
            let x = self.state[i];
            match i & 3 {
                0 => a ^= a << 13,
                1 => a ^= a >> 6,
                2 => a ^= a << 2,
                _ => a ^= a >> 16,
            }
            a = a.wrapping_add(self.state[i ^ 0x80]);

            let y = self.state[((x >> 2) & 0xff) as usize]
                .wrapping_add(a)
                .wrapping_add(b);
            self.state[i] = y;
            b = self.state[((y >> 10) & 0xff) as usize].wrapping_add(x);
            self.key_stream[i * 4..i * 4 + 4].copy_from_slice(&b.to_be_bytes());
        }

        self.a = a;
        self.b = b;
    }

    fn initialize_state(&mut self) {
        self.state.fill(0);
        self.a = 0;
        self.b = 0;
        self.c = 0;
        self.key_stream.fill(0);
        self.key_stream_pos = 0;

        let key = &self.working_key[..self.key_len];
        let mut chunks = key.chunks_exact(4);
        for (destination, chunk) in self.state.iter_mut().zip(chunks.by_ref()) {
            *destination = u32::from_le_bytes(chunk.try_into().expect("four-byte key chunk"));
        }
        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut final_word = [0u8; 4];
            final_word[..remainder.len()].copy_from_slice(remainder);
            self.state[self.key_len / 4] = u32::from_le_bytes(final_word);
        }

        let mut mix_state = [0x9e37_79b9u32; MIX_WORDS];
        for _ in 0..4 {
            Self::mix(&mut mix_state);
        }

        for _ in 0..2 {
            for offset in (0..STATE_WORDS).step_by(MIX_WORDS) {
                for (mix_word, state_word) in mix_state
                    .iter_mut()
                    .zip(&self.state[offset..offset + MIX_WORDS])
                {
                    *mix_word = mix_word.wrapping_add(*state_word);
                }
                Self::mix(&mut mix_state);
                self.state[offset..offset + MIX_WORDS].copy_from_slice(&mix_state);
            }
        }

        // BC generates once during initialization, then generates the first
        // externally visible block when position zero is processed.
        self.generate_key_stream();
    }

    #[allow(clippy::many_single_char_names)]
    fn mix(state: &mut [u32; MIX_WORDS]) {
        let [
            mut x0,
            mut x1,
            mut x2,
            mut x3,
            mut x4,
            mut x5,
            mut x6,
            mut x7,
        ] = *state;

        x0 ^= x1 << 11;
        x3 = x3.wrapping_add(x0);
        x1 = x1.wrapping_add(x2);
        x1 ^= x2 >> 2;
        x4 = x4.wrapping_add(x1);
        x2 = x2.wrapping_add(x3);
        x2 ^= x3 << 8;
        x5 = x5.wrapping_add(x2);
        x3 = x3.wrapping_add(x4);
        x3 ^= x4 >> 16;
        x6 = x6.wrapping_add(x3);
        x4 = x4.wrapping_add(x5);
        x4 ^= x5 << 10;
        x7 = x7.wrapping_add(x4);
        x5 = x5.wrapping_add(x6);
        x5 ^= x6 >> 4;
        x0 = x0.wrapping_add(x5);
        x6 = x6.wrapping_add(x7);
        x6 ^= x7 << 8;
        x1 = x1.wrapping_add(x6);
        x7 = x7.wrapping_add(x0);
        x7 ^= x0 >> 9;
        x2 = x2.wrapping_add(x7);
        x0 = x0.wrapping_add(x1);

        *state = [x0, x1, x2, x3, x4, x5, x6, x7];
    }

    fn next_byte(&mut self) -> u8 {
        if self.key_stream_pos == 0 {
            self.generate_key_stream();
        }
        let result = self.key_stream[self.key_stream_pos];
        self.key_stream_pos = (self.key_stream_pos + 1) & (KEYSTREAM_BYTES - 1);
        result
    }
}

impl Default for IsaacEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCipher for IsaacEngine {
    type Params<'a> = IsaacParams;
    type Error = StreamCipherError;

    fn algorithm_name(&self) -> &str {
        "ISAAC"
    }

    fn init(
        &mut self,
        _for_encryption: bool,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.working_key[..params.key_len].copy_from_slice(params.key());
        self.key_len = params.key_len;
        self.initialize_state();
        self.initialised = true;
        Ok(())
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

        let mut position = 0;
        while position < input.len() {
            if self.key_stream_pos == 0 {
                self.generate_key_stream();
            }
            let length = core::cmp::min(
                input.len() - position,
                KEYSTREAM_BYTES - self.key_stream_pos,
            );
            for i in 0..length {
                output[position + i] =
                    input[position + i] ^ self.key_stream[self.key_stream_pos + i];
            }
            position += length;
            self.key_stream_pos = (self.key_stream_pos + length) & (KEYSTREAM_BYTES - 1);
        }
        Ok(input.len())
    }

    fn reset(&mut self) {
        if self.initialised {
            self.initialize_state();
        }
    }
}
