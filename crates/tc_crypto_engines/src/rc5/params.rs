//! Validated RC5 initialization parameters (shared by both word sizes).

use alloc::vec::Vec;
use core::fmt;

use super::{RC5_DEFAULT_ROUNDS, RC5_MAX_KEY_BYTES, RC5_MAX_ROUNDS, Rc5Error};

/// Owned, validated RC5 key and round-count parameters.
pub struct Rc5Params {
    key: Vec<u8>,
    rounds: usize,
}

impl fmt::Debug for Rc5Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rc5Params")
            .field("key_len", &self.key.len())
            .field("rounds", &self.rounds)
            .finish()
    }
}

impl Rc5Params {
    /// Validates `key` with the standard twelve rounds.
    pub fn new(key: &[u8]) -> Result<Self, Rc5Error> {
        Self::with_rounds(key, RC5_DEFAULT_ROUNDS)
    }

    /// Validates `key` and an explicit round count.
    pub fn with_rounds(key: &[u8], rounds: usize) -> Result<Self, Rc5Error> {
        if key.is_empty() || key.len() > RC5_MAX_KEY_BYTES {
            return Err(Rc5Error::InvalidKeyLength(key.len()));
        }
        if rounds > RC5_MAX_ROUNDS {
            return Err(Rc5Error::InvalidRounds(rounds));
        }
        Ok(Self {
            key: key.to_vec(),
            rounds,
        })
    }

    /// The configured round count.
    pub const fn rounds(&self) -> usize {
        self.rounds
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_key_length() {
        assert!(matches!(
            Rc5Params::new(&[]),
            Err(Rc5Error::InvalidKeyLength(0))
        ));
        assert!(matches!(
            Rc5Params::new(&[0u8; 256]),
            Err(Rc5Error::InvalidKeyLength(256))
        ));
    }

    #[test]
    fn rejects_invalid_rounds() {
        assert!(matches!(
            Rc5Params::with_rounds(&[0u8; 8], 256),
            Err(Rc5Error::InvalidRounds(256))
        ));
    }

    #[test]
    fn new_defaults_to_twelve_rounds() {
        assert_eq!(Rc5Params::new(&[0u8; 8]).unwrap().rounds(), 12);
    }
}
