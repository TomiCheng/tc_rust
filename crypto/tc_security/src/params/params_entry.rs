use std::fmt::{self, Display, Formatter};

use super::{AnyParams, ParamsGenerator};
use crate::cipher::CipherEntry;

#[derive(Clone, Copy, Debug)]
pub struct ParamsEntry {
    cipher: &'static CipherEntry,
}

impl ParamsEntry {
    pub(super) const fn new(cipher: &'static CipherEntry) -> Self {
        Self { cipher }
    }

    pub fn name(&self) -> &'static str {
        self.cipher.name()
    }

    pub(super) fn cipher_entry(&self) -> &'static CipherEntry {
        self.cipher
    }

    pub fn generator(&self, key: AnyParams) -> ParamsGenerator {
        ParamsGenerator::new(*self, key)
    }
}

impl Display for ParamsEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.cipher.fmt(f)
    }
}
