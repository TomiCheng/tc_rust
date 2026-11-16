use core::any::Any;

use crate::Params;

// The params of the RC2 key generator: the length of the key in bytes, and the effective key size
// in bits, which is that of the whole key unless set. They are not checked until init
#[cfg(feature = "rc2")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rc2KeyGenParams {
    key_bytes: usize,
    effective_key_bits: Option<usize>,
}

#[cfg(feature = "rc2")]
impl Rc2KeyGenParams {
    pub const fn new(key_bytes: usize) -> Self {
        Self {
            key_bytes,
            effective_key_bits: None,
        }
    }

    pub const fn with_effective_key_bits(mut self, effective_key_bits: usize) -> Self {
        self.effective_key_bits = Some(effective_key_bits);
        self
    }

    pub const fn key_bytes(&self) -> usize {
        self.key_bytes
    }

    pub const fn effective_key_bits(&self) -> Option<usize> {
        self.effective_key_bits
    }
}

#[cfg(feature = "rc2")]
impl Params for Rc2KeyGenParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// The params of the RC5 and RC5-64 key generators: the length of the key in bytes, and the number of
// rounds, 12 unless set. They are not checked until init
#[cfg(any(feature = "rc5", feature = "rc5-64"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rc5KeyGenParams {
    key_bytes: usize,
    rounds: Option<usize>,
}

#[cfg(any(feature = "rc5", feature = "rc5-64"))]
impl Rc5KeyGenParams {
    pub const fn new(key_bytes: usize) -> Self {
        Self {
            key_bytes,
            rounds: None,
        }
    }

    pub const fn with_rounds(mut self, rounds: usize) -> Self {
        self.rounds = Some(rounds);
        self
    }

    pub const fn key_bytes(&self) -> usize {
        self.key_bytes
    }

    pub const fn rounds(&self) -> Option<usize> {
        self.rounds
    }
}

#[cfg(any(feature = "rc5", feature = "rc5-64"))]
impl Params for Rc5KeyGenParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// The params of the GOST 28147 key generator: the S-box, the default one of tc_gost28147 unless
// set, such as to one of gost28147_s_box. The key is always 32 bytes. Not checked until init
#[cfg(feature = "gost28147")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Gost28147KeyGenParams {
    s_box: Option<Vec<u8>>,
}

#[cfg(feature = "gost28147")]
impl Gost28147KeyGenParams {
    pub const fn new() -> Self {
        Self { s_box: None }
    }

    pub fn with_s_box(mut self, s_box: Vec<u8>) -> Self {
        self.s_box = Some(s_box);
        self
    }

    pub fn s_box(&self) -> Option<&[u8]> {
        self.s_box.as_deref()
    }
}

#[cfg(feature = "gost28147")]
impl Params for Gost28147KeyGenParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
