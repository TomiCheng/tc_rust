//! Original ChaCha stream cipher, ported from Bouncy Castle's `ChaChaEngine`.
//!
//! This is the original construction with a 64-bit counter and 64-bit nonce,
//! not the later IETF ChaCha7539 construction with a 96-bit nonce.

use tc_crypto_core::StreamCipher;

use crate::StreamCipherError;

/// Default ChaCha round count.
pub const CHACHA_DEFAULT_ROUNDS: usize = 20;

/// Original ChaCha nonce size in bytes.
pub const CHACHA_NONCE_BYTES: usize = 8;

/// Original ChaCha's smaller supported key size in bytes.
pub const CHACHA_MIN_KEY_BYTES: usize = 16;

/// Original ChaCha's larger supported key size in bytes.
pub const CHACHA_MAX_KEY_BYTES: usize = 32;

pub(crate) const CHACHA_BLOCK_BYTES: usize = 64;
const STATE_WORDS: usize = 16;
const CHACHA_MAX_ROUNDS: usize = i32::MAX as usize - 1;

const TAU: [u32; 4] = [0x6170_7865, 0x3120_646e, 0x7962_2d36, 0x6b20_6574];
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Validated original-ChaCha key and nonce parameters.
pub struct ChaChaParams {
    key: [u8; CHACHA_MAX_KEY_BYTES],
    key_len: usize,
    nonce: [u8; CHACHA_NONCE_BYTES],
}

impl ChaChaParams {
    /// Validates and copies a 16- or 32-byte key and an 8-byte nonce.
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, StreamCipherError> {
        if key.len() != CHACHA_MIN_KEY_BYTES && key.len() != CHACHA_MAX_KEY_BYTES {
            return Err(StreamCipherError::InvalidKeyLength(key.len()));
        }
        if nonce.len() != CHACHA_NONCE_BYTES {
            return Err(StreamCipherError::InvalidNonceLength {
                expected: CHACHA_NONCE_BYTES,
                actual: nonce.len(),
            });
        }

        let mut owned_key = [0u8; CHACHA_MAX_KEY_BYTES];
        owned_key[..key.len()].copy_from_slice(key);
        let mut owned_nonce = [0u8; CHACHA_NONCE_BYTES];
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

impl core::fmt::Debug for ChaChaParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChaChaParams")
            .field("key_len", &self.key_len)
            .field("nonce_len", &CHACHA_NONCE_BYTES)
            .finish()
    }
}

/// The original ChaCha stream cipher engine (BC `ChaChaEngine`).
pub struct ChaChaEngine {
    core: ChaChaCore,
    name: [u8; 32],
    name_len: usize,
}

impl ChaChaEngine {
    /// Creates a 20-round original-ChaCha engine.
    pub fn new() -> Self {
        Self::with_rounds(CHACHA_DEFAULT_ROUNDS).expect("default ChaCha rounds are valid")
    }

    /// Creates an original-ChaCha engine with a positive, even round count.
    pub fn with_rounds(rounds: usize) -> Result<Self, StreamCipherError> {
        if rounds == 0 || rounds & 1 != 0 || rounds > CHACHA_MAX_ROUNDS {
            return Err(StreamCipherError::InvalidRounds(rounds));
        }
        let (name, name_len) = algorithm_name(rounds);
        Ok(Self {
            core: ChaChaCore::new(rounds),
            name,
            name_len,
        })
    }
}

impl Default for ChaChaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCipher for ChaChaEngine {
    type Params<'a> = ChaChaParams;
    type Error = StreamCipherError;

    fn algorithm_name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).expect("ChaCha algorithm name is ASCII")
    }

    fn init(
        &mut self,
        _for_encryption: bool,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.core.init_original(params.key(), &params.nonce);
        Ok(())
    }

    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
        self.core.return_byte(input)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.core.process_bytes(input, output)
    }

    fn reset(&mut self) {
        self.core.reset_original();
    }
}

fn algorithm_name(rounds: usize) -> ([u8; 32], usize) {
    let mut name = [0u8; 32];
    let prefix = b"ChaCha";
    name[..prefix.len()].copy_from_slice(prefix);

    let mut digits = [0u8; 10];
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

pub(crate) struct ChaChaCore {
    rounds: usize,
    pub(crate) state: [u32; STATE_WORDS],
    key_stream: [u8; CHACHA_BLOCK_BYTES],
    index: usize,
    limit_word0: u32,
    limit_word1: u32,
    limit_word2: u32,
    initialised: bool,
    counter_mode: CounterMode,
}

#[derive(Clone, Copy)]
enum CounterMode {
    Original,
    Ietf,
}

impl ChaChaCore {
    pub(crate) fn new(rounds: usize) -> Self {
        Self {
            rounds,
            state: [0u32; STATE_WORDS],
            key_stream: [0u8; CHACHA_BLOCK_BYTES],
            index: 0,
            limit_word0: 0,
            limit_word1: 0,
            limit_word2: 0,
            initialised: false,
            counter_mode: CounterMode::Original,
        }
    }

    fn init_original(&mut self, key: &[u8], nonce: &[u8; CHACHA_NONCE_BYTES]) {
        self.state.fill(0);
        set_chacha_key(&mut self.state, key);
        for (i, chunk) in nonce.chunks_exact(4).enumerate() {
            self.state[14 + i] =
                u32::from_le_bytes(chunk.try_into().expect("four-byte nonce chunk"));
        }
        self.counter_mode = CounterMode::Original;
        self.reset_original();
        self.initialised = true;
    }

    pub(crate) fn init_ietf(&mut self, key: &[u8; 32], nonce: &[u8; 12]) {
        self.state.fill(0);
        set_chacha_key(&mut self.state, key);
        for (i, chunk) in nonce.chunks_exact(4).enumerate() {
            self.state[13 + i] =
                u32::from_le_bytes(chunk.try_into().expect("four-byte nonce chunk"));
        }
        self.counter_mode = CounterMode::Ietf;
        self.reset_ietf();
        self.initialised = true;
    }

    fn generate_key_stream(&mut self) {
        self.key_stream = chacha_core(self.rounds, &self.state);
    }

    fn advance_original_counter(&mut self) {
        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 {
            self.state[13] = self.state[13].wrapping_add(1);
        }
    }

    fn advance_counter(&mut self) -> Result<(), StreamCipherError> {
        match self.counter_mode {
            CounterMode::Original => {
                self.advance_original_counter();
                Ok(())
            }
            CounterMode::Ietf => {
                self.state[12] = self.state[12].wrapping_add(1);
                if self.state[12] == 0 {
                    Err(StreamCipherError::CounterExhausted)
                } else {
                    Ok(())
                }
            }
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
            self.advance_counter()?;
        }
        let output = input ^ self.key_stream[self.index];
        self.index = (self.index + 1) & (CHACHA_BLOCK_BYTES - 1);
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
                self.advance_counter()?;
            }
            *destination = *source ^ self.key_stream[self.index];
            self.index = (self.index + 1) & (CHACHA_BLOCK_BYTES - 1);
        }
        Ok(input.len())
    }

    pub(crate) fn reset_original(&mut self) {
        self.index = 0;
        self.limit_word0 = 0;
        self.limit_word1 = 0;
        self.limit_word2 = 0;
        self.state[12] = 0;
        self.state[13] = 0;
    }

    pub(crate) fn reset_ietf(&mut self) {
        self.index = 0;
        self.limit_word0 = 0;
        self.limit_word1 = 0;
        self.limit_word2 = 0;
        self.state[12] = 0;
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

pub(crate) fn set_chacha_key(state: &mut [u32; STATE_WORDS], key: &[u8]) {
    let constants = if key.len() == CHACHA_MIN_KEY_BYTES {
        TAU
    } else {
        SIGMA
    };
    state[..4].copy_from_slice(&constants);
    for (i, chunk) in key[..16].chunks_exact(4).enumerate() {
        state[4 + i] = u32::from_le_bytes(chunk.try_into().expect("four-byte key chunk"));
    }
    for (i, chunk) in key[key.len() - 16..].chunks_exact(4).enumerate() {
        state[8 + i] = u32::from_le_bytes(chunk.try_into().expect("four-byte key chunk"));
    }
}

pub(crate) fn chacha_core(rounds: usize, input: &[u32; STATE_WORDS]) -> [u8; CHACHA_BLOCK_BYTES] {
    let x = chacha_permutation(rounds, input);

    let mut output = [0u8; CHACHA_BLOCK_BYTES];
    for ((chunk, word), original) in output.chunks_exact_mut(4).zip(x).zip(input) {
        chunk.copy_from_slice(&word.wrapping_add(*original).to_le_bytes());
    }
    output
}

pub(crate) fn chacha_permutation(rounds: usize, input: &[u32; STATE_WORDS]) -> [u32; STATE_WORDS] {
    let mut x = *input;
    for _ in (0..rounds).step_by(2) {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);

        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
    }

    x
}

#[inline]
fn quarter_round(state: &mut [u32; STATE_WORDS], ai: usize, bi: usize, ci: usize, di: usize) {
    let mut a = state[ai];
    let mut b = state[bi];
    let mut c = state[ci];
    let mut d = state[di];

    a = a.wrapping_add(b);
    d = (d ^ a).rotate_left(16);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_left(12);
    a = a.wrapping_add(b);
    d = (d ^ a).rotate_left(8);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_left(7);

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
        let mut core = ChaChaCore::new(CHACHA_DEFAULT_ROUNDS);
        core.limit_word0 = u32::MAX;
        core.limit_word1 = u32::MAX;
        core.limit_word2 = 0x1f;
        assert!(core.limit_exceeded_by(1));
    }

    #[test]
    fn ietf_counter_wrap_is_rejected() {
        let mut core = ChaChaCore::new(CHACHA_DEFAULT_ROUNDS);
        core.init_ietf(&[0u8; 32], &[0u8; 12]);
        core.state[12] = u32::MAX;
        assert_eq!(
            core.process_bytes(&[0u8; 1], &mut [0u8; 1]),
            Err(StreamCipherError::CounterExhausted)
        );
    }
}
