//! Salsa20 stream cipher, ported from Bouncy Castle's `Salsa20Engine`.
//!
//! Salsa20 accepts 128- or 256-bit keys and a 64-bit nonce. The default uses
//! 20 rounds; positive even custom round counts are also supported.

use tc_crypto_core::StreamCipher;

use crate::StreamCipherError;

/// Default Salsa20 round count.
pub const SALSA20_DEFAULT_ROUNDS: usize = 20;

/// Salsa20 nonce size in bytes.
pub const SALSA20_NONCE_BYTES: usize = 8;

/// Salsa20's smaller supported key size in bytes.
pub const SALSA20_MIN_KEY_BYTES: usize = 16;

/// Salsa20's larger supported key size in bytes.
pub const SALSA20_MAX_KEY_BYTES: usize = 32;

pub(crate) const SALSA20_BLOCK_BYTES: usize = 64;
const STATE_WORDS: usize = 16;
const SALSA20_MAX_ROUNDS: usize = i32::MAX as usize - 1;

const TAU: [u32; 4] = [0x6170_7865, 0x3120_646e, 0x7962_2d36, 0x6b20_6574];
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Validated Salsa20 key and nonce parameters.
pub struct Salsa20Params {
    key: [u8; SALSA20_MAX_KEY_BYTES],
    key_len: usize,
    nonce: [u8; SALSA20_NONCE_BYTES],
}

impl Salsa20Params {
    /// Validates and copies a 16- or 32-byte key and an 8-byte nonce.
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, StreamCipherError> {
        if key.len() != SALSA20_MIN_KEY_BYTES && key.len() != SALSA20_MAX_KEY_BYTES {
            return Err(StreamCipherError::InvalidKeyLength(key.len()));
        }
        if nonce.len() != SALSA20_NONCE_BYTES {
            return Err(StreamCipherError::InvalidNonceLength {
                expected: SALSA20_NONCE_BYTES,
                actual: nonce.len(),
            });
        }

        let mut owned_key = [0u8; SALSA20_MAX_KEY_BYTES];
        owned_key[..key.len()].copy_from_slice(key);
        let mut owned_nonce = [0u8; SALSA20_NONCE_BYTES];
        owned_nonce.copy_from_slice(nonce);
        Ok(Self {
            key: owned_key,
            key_len: key.len(),
            nonce: owned_nonce,
        })
    }

    fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }
}

impl core::fmt::Debug for Salsa20Params {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Salsa20Params")
            .field("key_len", &self.key_len)
            .field("nonce_len", &SALSA20_NONCE_BYTES)
            .finish()
    }
}

/// The Salsa20 stream cipher engine (BC `Salsa20Engine`).
pub struct Salsa20Engine {
    core: Salsa20Core,
    name: [u8; 32],
    name_len: usize,
}

impl Salsa20Engine {
    /// Creates a 20-round Salsa20 engine.
    pub fn new() -> Self {
        Self::with_rounds(SALSA20_DEFAULT_ROUNDS).expect("default Salsa20 rounds are valid")
    }

    /// Creates a Salsa20 engine with a positive, even round count.
    pub fn with_rounds(rounds: usize) -> Result<Self, StreamCipherError> {
        if rounds == 0 || rounds & 1 != 0 || rounds > SALSA20_MAX_ROUNDS {
            return Err(StreamCipherError::InvalidRounds(rounds));
        }
        let (name, name_len) = algorithm_name(rounds);
        Ok(Self {
            core: Salsa20Core::new(rounds),
            name,
            name_len,
        })
    }
}

impl Default for Salsa20Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCipher for Salsa20Engine {
    type Params<'a> = Salsa20Params;
    type Error = StreamCipherError;

    fn algorithm_name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).expect("Salsa20 algorithm name is ASCII")
    }

    fn init(
        &mut self,
        _for_encryption: bool,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.core.init_salsa20(params.key(), &params.nonce);
        Ok(())
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

fn algorithm_name(rounds: usize) -> ([u8; 32], usize) {
    let mut name = [0u8; 32];
    let prefix = if rounds == SALSA20_DEFAULT_ROUNDS {
        b"Salsa20".as_slice()
    } else {
        b"Salsa20/".as_slice()
    };
    name[..prefix.len()].copy_from_slice(prefix);
    if rounds == SALSA20_DEFAULT_ROUNDS {
        return (name, prefix.len());
    }

    let mut digits = [0u8; 20];
    let mut value = rounds;
    let mut digit_count = 0;
    while value != 0 {
        digits[digit_count] = b'0' + (value % 10) as u8;
        digit_count += 1;
        value /= 10;
    }
    for i in 0..digit_count {
        name[prefix.len() + i] = digits[digit_count - 1 - i];
    }
    (name, prefix.len() + digit_count)
}

pub(crate) struct Salsa20Core {
    rounds: usize,
    pub(crate) state: [u32; STATE_WORDS],
    key_stream: [u8; SALSA20_BLOCK_BYTES],
    index: usize,
    limit_word0: u32,
    limit_word1: u32,
    limit_word2: u32,
    initialised: bool,
}

impl Salsa20Core {
    pub(crate) fn new(rounds: usize) -> Self {
        Self {
            rounds,
            state: [0u32; STATE_WORDS],
            key_stream: [0u8; SALSA20_BLOCK_BYTES],
            index: 0,
            limit_word0: 0,
            limit_word1: 0,
            limit_word2: 0,
            initialised: false,
        }
    }

    fn init_salsa20(&mut self, key: &[u8], nonce: &[u8; SALSA20_NONCE_BYTES]) {
        self.state.fill(0);
        set_salsa_key(&mut self.state, key, nonce);
        self.reset();
        self.initialised = true;
    }

    pub(crate) fn finish_initialization(&mut self) {
        self.reset();
        self.initialised = true;
    }

    fn generate_key_stream(&mut self) {
        let output = salsa_core(self.rounds, &self.state);
        for (chunk, word) in self.key_stream.chunks_exact_mut(4).zip(output) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
    }

    fn advance_counter(&mut self) {
        self.state[8] = self.state[8].wrapping_add(1);
        if self.state[8] == 0 {
            self.state[9] = self.state[9].wrapping_add(1);
        }
    }

    pub(crate) fn return_byte(&mut self, input: u8) -> Result<u8, StreamCipherError> {
        if !self.initialised {
            return Err(StreamCipherError::NotInitialised);
        }
        if self.limit_exceeded_by(1) {
            return Err(StreamCipherError::MaxBytesExceeded);
        }
        if self.index == 0 {
            self.generate_key_stream();
            self.advance_counter();
        }
        let output = input ^ self.key_stream[self.index];
        self.index = (self.index + 1) & (SALSA20_BLOCK_BYTES - 1);
        Ok(output)
    }

    pub(crate) fn process_bytes(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, StreamCipherError> {
        if !self.initialised {
            return Err(StreamCipherError::NotInitialised);
        }
        if output.len() < input.len() {
            return Err(StreamCipherError::OutputBufferTooShort);
        }
        if self.limit_exceeded_by(input.len()) {
            return Err(StreamCipherError::MaxBytesExceeded);
        }

        for (source, destination) in input.iter().zip(output.iter_mut()) {
            if self.index == 0 {
                self.generate_key_stream();
                self.advance_counter();
            }
            *destination = *source ^ self.key_stream[self.index];
            self.index = (self.index + 1) & (SALSA20_BLOCK_BYTES - 1);
        }
        Ok(input.len())
    }

    pub(crate) fn reset(&mut self) {
        self.index = 0;
        self.limit_word0 = 0;
        self.limit_word1 = 0;
        self.limit_word2 = 0;
        self.state[8] = 0;
        self.state[9] = 0;
    }

    fn limit_exceeded_by(&mut self, mut length: usize) -> bool {
        while length != 0 {
            let chunk = core::cmp::min(length, u32::MAX as usize) as u32;
            let old = self.limit_word0;
            self.limit_word0 = self.limit_word0.wrapping_add(chunk);
            if self.limit_word0 < old {
                self.limit_word1 = self.limit_word1.wrapping_add(1);
                if self.limit_word1 == 0 {
                    self.limit_word2 = self.limit_word2.wrapping_add(1);
                }
            }
            length -= chunk as usize;
        }
        self.limit_word2 & 0x20 != 0
    }
}

pub(crate) fn set_salsa_key(state: &mut [u32; STATE_WORDS], key: &[u8], nonce: &[u8]) {
    let constants = if key.len() == SALSA20_MIN_KEY_BYTES {
        TAU
    } else {
        SIGMA
    };
    state[0] = constants[0];
    state[5] = constants[1];
    state[10] = constants[2];
    state[15] = constants[3];

    for (i, chunk) in key[..16].chunks_exact(4).enumerate() {
        state[1 + i] = u32::from_le_bytes(chunk.try_into().expect("four-byte key chunk"));
    }
    for (i, chunk) in key[key.len() - 16..].chunks_exact(4).enumerate() {
        state[11 + i] = u32::from_le_bytes(chunk.try_into().expect("four-byte key chunk"));
    }
    for (i, chunk) in nonce[..8].chunks_exact(4).enumerate() {
        state[6 + i] = u32::from_le_bytes(chunk.try_into().expect("four-byte nonce chunk"));
    }
}

pub(crate) fn salsa_core(rounds: usize, input: &[u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut x = *input;
    for _ in (0..rounds).step_by(2) {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 5, 9, 13, 1);
        quarter_round(&mut x, 10, 14, 2, 6);
        quarter_round(&mut x, 15, 3, 7, 11);

        quarter_round(&mut x, 0, 1, 2, 3);
        quarter_round(&mut x, 5, 6, 7, 4);
        quarter_round(&mut x, 10, 11, 8, 9);
        quarter_round(&mut x, 15, 12, 13, 14);
    }
    for (word, original) in x.iter_mut().zip(input) {
        *word = word.wrapping_add(*original);
    }
    x
}

#[inline]
fn quarter_round(state: &mut [u32; STATE_WORDS], ai: usize, bi: usize, ci: usize, di: usize) {
    let mut a = state[ai];
    let mut b = state[bi];
    let mut c = state[ci];
    let mut d = state[di];

    b ^= a.wrapping_add(d).rotate_left(7);
    c ^= b.wrapping_add(a).rotate_left(9);
    d ^= c.wrapping_add(b).rotate_left(13);
    a ^= d.wrapping_add(c).rotate_left(18);

    state[ai] = a;
    state[bi] = b;
    state[ci] = c;
    state[di] = d;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bc_limit_counter_boundary_is_enforced() {
        let mut core = Salsa20Core::new(SALSA20_DEFAULT_ROUNDS);
        core.limit_word0 = u32::MAX;
        core.limit_word1 = u32::MAX;
        core.limit_word2 = 0x1f;
        assert!(core.limit_exceeded_by(1));
    }
}
