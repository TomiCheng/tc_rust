//! VMPC and VMPC-KSA3 stream ciphers, ported from Bouncy Castle's
//! `VmpcEngine` and `VmpcKsa3Engine`.
//!
//! Both algorithms use the same keystream generator. VMPC initializes the
//! permutation with key and IV scheduling rounds; VMPC-KSA3 adds a third key
//! scheduling round.

use tc_cipher_core::{StreamCipher, StreamCipherInit};

use crate::StreamCipherError;

const STATE_BYTES: usize = 256;
const KSA_STEPS: usize = 768;

/// Minimum VMPC key size in bytes.
pub const VMPC_MIN_KEY_BYTES: usize = 16;

/// Maximum VMPC key size in bytes.
pub const VMPC_MAX_KEY_BYTES: usize = 64;

/// Minimum VMPC IV size in bytes.
pub const VMPC_MIN_IV_BYTES: usize = 16;

/// Maximum VMPC IV size in bytes.
pub const VMPC_MAX_IV_BYTES: usize = 64;

/// Validated VMPC key and IV parameters.
pub struct VmpcParams {
    key: [u8; VMPC_MAX_KEY_BYTES],
    key_len: usize,
    iv: [u8; VMPC_MAX_IV_BYTES],
    iv_len: usize,
}

impl VmpcParams {
    /// Validates and copies a 16-64 byte key and 16-64 byte IV.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, StreamCipherError> {
        if !(VMPC_MIN_KEY_BYTES..=VMPC_MAX_KEY_BYTES).contains(&key.len()) {
            return Err(StreamCipherError::InvalidKeyLength(key.len()));
        }
        if !(VMPC_MIN_IV_BYTES..=VMPC_MAX_IV_BYTES).contains(&iv.len()) {
            return Err(StreamCipherError::InvalidIvLength(iv.len()));
        }

        let mut owned_key = [0u8; VMPC_MAX_KEY_BYTES];
        owned_key[..key.len()].copy_from_slice(key);
        let mut owned_iv = [0u8; VMPC_MAX_IV_BYTES];
        owned_iv[..iv.len()].copy_from_slice(iv);
        Ok(Self {
            key: owned_key,
            key_len: key.len(),
            iv: owned_iv,
            iv_len: iv.len(),
        })
    }

    fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }

    fn iv(&self) -> &[u8] {
        &self.iv[..self.iv_len]
    }
}

impl core::fmt::Debug for VmpcParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VmpcParams")
            .field("key_len", &self.key_len)
            .field("iv_len", &self.iv_len)
            .finish()
    }
}

struct VmpcCore {
    state: [u8; STATE_BYTES],
    n: u8,
    s: u8,
    working_key: [u8; VMPC_MAX_KEY_BYTES],
    key_len: usize,
    working_iv: [u8; VMPC_MAX_IV_BYTES],
    iv_len: usize,
    ksa3: bool,
    initialised: bool,
}

impl VmpcCore {
    const fn new(ksa3: bool) -> Self {
        Self {
            state: [0u8; STATE_BYTES],
            n: 0,
            s: 0,
            working_key: [0u8; VMPC_MAX_KEY_BYTES],
            key_len: 0,
            working_iv: [0u8; VMPC_MAX_IV_BYTES],
            iv_len: 0,
            ksa3,
            initialised: false,
        }
    }

    fn init(&mut self, params: &VmpcParams) {
        self.working_key[..params.key_len].copy_from_slice(params.key());
        self.key_len = params.key_len;
        self.working_iv[..params.iv_len].copy_from_slice(params.iv());
        self.iv_len = params.iv_len;
        self.initialize_state();
        self.initialised = true;
    }

    fn initialize_state(&mut self) {
        self.n = 0;
        self.s = 0;
        for (i, value) in self.state.iter_mut().enumerate() {
            *value = i as u8;
        }

        ksa_round(
            &mut self.state,
            &mut self.s,
            &self.working_key[..self.key_len],
        );
        ksa_round(
            &mut self.state,
            &mut self.s,
            &self.working_iv[..self.iv_len],
        );
        if self.ksa3 {
            ksa_round(
                &mut self.state,
                &mut self.s,
                &self.working_key[..self.key_len],
            );
        }
    }

    fn return_byte(&mut self, input: u8) -> Result<u8, StreamCipherError> {
        if !self.initialised {
            return Err(StreamCipherError::NotInitialised);
        }
        Ok(input ^ self.next_keystream_byte())
    }

    fn process_bytes(
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
        for (source, destination) in input.iter().zip(output.iter_mut()) {
            *destination = *source ^ self.next_keystream_byte();
        }
        Ok(input.len())
    }

    fn next_keystream_byte(&mut self) -> u8 {
        let n = self.n as usize;
        let pn = self.state[n];
        self.s = self.state[self.s.wrapping_add(pn) as usize];
        let s = self.s as usize;
        let ps = self.state[s];
        let output = self.state[self.state[ps as usize].wrapping_add(1) as usize];
        self.state[n] = ps;
        self.state[s] = pn;
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
    for m in 0..KSA_STEPS {
        let index = m & 0xff;
        let pm = state[index];
        *s = state[s.wrapping_add(pm).wrapping_add(input[m % input.len()]) as usize];
        state[index] = state[*s as usize];
        state[*s as usize] = pm;
    }
}

/// VMPC stream cipher engine (BC `VmpcEngine`).
pub struct VmpcEngine {
    core: VmpcCore,
}

impl VmpcEngine {
    /// Creates an uninitialized VMPC engine.
    pub const fn new() -> Self {
        Self {
            core: VmpcCore::new(false),
        }
    }
}

impl Default for VmpcEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCipher for VmpcEngine {
    type Error = StreamCipherError;

    fn algorithm_name(&self) -> &str {
        "VMPC"
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

impl StreamCipherInit for VmpcEngine {
    type Params<'a> = VmpcParams;

    fn init(
        &mut self,
        _for_encryption: bool,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.core.init(params);
        Ok(())
    }
}

/// VMPC-KSA3 stream cipher engine (BC `VmpcKsa3Engine`).
pub struct VmpcKsa3Engine {
    core: VmpcCore,
}

impl VmpcKsa3Engine {
    /// Creates an uninitialized VMPC-KSA3 engine.
    pub const fn new() -> Self {
        Self {
            core: VmpcCore::new(true),
        }
    }
}

impl Default for VmpcKsa3Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCipher for VmpcKsa3Engine {
    type Error = StreamCipherError;

    fn algorithm_name(&self) -> &str {
        "VMPC-KSA3"
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

impl StreamCipherInit for VmpcKsa3Engine {
    type Params<'a> = VmpcParams;

    fn init(
        &mut self,
        _for_encryption: bool,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        self.core.init(params);
        Ok(())
    }
}
