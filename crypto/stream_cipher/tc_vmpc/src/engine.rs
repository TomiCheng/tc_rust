//! VMPC and VMPC-KSA3 engines.

use ::core::fmt;

use tc_cipher::{CipherDirection, InitError, StreamCipher, StreamCipherInit, StreamError};
use tc_crypto::AlgorithmName;
use tc_params::KeyWithIvParams;

use crate::{MAX_IV_BYTES, MAX_KEY_BYTES, MIN_IV_BYTES, MIN_KEY_BYTES};

const STATE_BYTES: usize = 256;
const KSA_STEPS: usize = 768;

struct State {
    permutation: [u8; STATE_BYTES],
    n: u8,
    s: u8,
    working_key: [u8; MAX_KEY_BYTES],
    key_len: usize,
    working_iv: [u8; MAX_IV_BYTES],
    iv_len: usize,
    ksa3: bool,
    initialised: bool,
}

impl State {
    const fn new(ksa3: bool) -> Self {
        Self {
            permutation: [0; STATE_BYTES],
            n: 0,
            s: 0,
            working_key: [0; MAX_KEY_BYTES],
            key_len: 0,
            working_iv: [0; MAX_IV_BYTES],
            iv_len: 0,
            ksa3,
            initialised: false,
        }
    }

    fn init(&mut self, key: &[u8], iv: &[u8]) {
        self.working_key.fill(0);
        self.working_key[..key.len()].copy_from_slice(key);
        self.key_len = key.len();
        self.working_iv.fill(0);
        self.working_iv[..iv.len()].copy_from_slice(iv);
        self.iv_len = iv.len();
        self.initialize_state();
        self.initialised = true;
    }

    fn initialize_state(&mut self) {
        self.n = 0;
        self.s = 0;
        for (index, value) in self.permutation.iter_mut().enumerate() {
            *value = index as u8;
        }
        ksa_round(
            &mut self.permutation,
            &mut self.s,
            &self.working_key[..self.key_len],
        );
        ksa_round(
            &mut self.permutation,
            &mut self.s,
            &self.working_iv[..self.iv_len],
        );
        if self.ksa3 {
            ksa_round(
                &mut self.permutation,
                &mut self.s,
                &self.working_key[..self.key_len],
            );
        }
    }

    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        Ok(input ^ self.next_byte())
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
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

    fn next_byte(&mut self) -> u8 {
        let n = self.n as usize;
        let pn = self.permutation[n];
        self.s = self.permutation[self.s.wrapping_add(pn) as usize];
        let s = self.s as usize;
        let ps = self.permutation[s];
        let output = self.permutation[self.permutation[ps as usize].wrapping_add(1) as usize];
        self.permutation[n] = ps;
        self.permutation[s] = pn;
        self.n = self.n.wrapping_add(1);
        output
    }

    fn reset(&mut self) {
        if self.initialised {
            self.initialize_state();
        }
    }
}

fn ksa_round(state: &mut [u8; STATE_BYTES], s: &mut u8, input: &[u8]) {
    for step in 0..KSA_STEPS {
        let index = step & 0xff;
        let value = state[index];
        *s = state[s
            .wrapping_add(value)
            .wrapping_add(input[step % input.len()]) as usize];
        state[index] = state[*s as usize];
        state[*s as usize] = value;
    }
}

fn validate<P: KeyWithIvParams + ?Sized>(params: &P) -> Result<(&[u8], &[u8]), InitError> {
    let key = params.key();
    if !(MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&key.len()) {
        return Err(InitError::InvalidKeyLength(key.len()));
    }
    let iv = params.iv();
    if !(MIN_IV_BYTES..=MAX_IV_BYTES).contains(&iv.len()) {
        return Err(InitError::InvalidIvLength(iv.len()));
    }
    Ok((key, iv))
}

/// VMPC stream cipher engine.
pub struct VmpcEngine {
    state: State,
}

impl VmpcEngine {
    /// Creates an uninitialised VMPC engine.
    pub const fn new() -> Self {
        Self {
            state: State::new(false),
        }
    }
}

impl Default for VmpcEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for VmpcEngine {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("VMPC")
    }
}

impl StreamCipher for VmpcEngine {
    type Error = StreamError;

    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
        self.state.return_byte(input)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.state.process_bytes(input, output)
    }

    fn reset(&mut self) {
        self.state.reset();
    }
}

impl<P: KeyWithIvParams + ?Sized> StreamCipherInit<P> for VmpcEngine {
    type Error = InitError;

    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        let (key, iv) = validate(params)?;
        self.state.init(key, iv);
        Ok(())
    }
}

/// VMPC-KSA3 stream cipher engine.
pub struct VmpcKsa3Engine {
    state: State,
}

impl VmpcKsa3Engine {
    /// Creates an uninitialised VMPC-KSA3 engine.
    pub const fn new() -> Self {
        Self {
            state: State::new(true),
        }
    }
}

impl Default for VmpcKsa3Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlgorithmName for VmpcKsa3Engine {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("VMPC-KSA3")
    }
}

impl StreamCipher for VmpcKsa3Engine {
    type Error = StreamError;

    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
        self.state.return_byte(input)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.state.process_bytes(input, output)
    }

    fn reset(&mut self) {
        self.state.reset();
    }
}

impl<P: KeyWithIvParams + ?Sized> StreamCipherInit<P> for VmpcKsa3Engine {
    type Error = InitError;

    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        let (key, iv) = validate(params)?;
        self.state.init(key, iv);
        Ok(())
    }
}
