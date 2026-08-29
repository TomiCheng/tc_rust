//! Validated RC5 initialization parameters (shared by both word sizes).

use core::fmt;

use super::{BlockCipherError, RC5_DEFAULT_ROUNDS, RC5_MAX_KEY_BYTES, RC5_MAX_ROUNDS};

/// Owned, validated RC5 key and round-count parameters.
pub struct Rc5Params {
    key: [u8; RC5_MAX_KEY_BYTES],
    key_len: usize,
    rounds: usize,
}

impl fmt::Debug for Rc5Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rc5Params")
            .field("key_len", &self.key_len)
            .field("rounds", &self.rounds)
            .finish()
    }
}

impl Rc5Params {
    /// Validates `key` with the standard twelve rounds.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        Self::with_rounds(key, RC5_DEFAULT_ROUNDS)
    }

    /// Validates `key` and an explicit round count.
    pub fn with_rounds(key: &[u8], rounds: usize) -> Result<Self, BlockCipherError> {
        if key.is_empty() || key.len() > RC5_MAX_KEY_BYTES {
            return Err(BlockCipherError::InvalidKeyLength(key.len()));
        }
        if rounds > RC5_MAX_ROUNDS {
            return Err(BlockCipherError::InvalidRounds(rounds));
        }

        let mut key_buffer = [0_u8; RC5_MAX_KEY_BYTES];
        key_buffer[..key.len()].copy_from_slice(key);

        Ok(Self {
            key: key_buffer,
            key_len: key.len(),
            rounds,
        })
    }

    /// The configured round count.
    pub const fn rounds(&self) -> usize {
        self.rounds
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_key_length() {
        assert!(matches!(
            Rc5Params::new(&[]),
            Err(BlockCipherError::InvalidKeyLength(0))
        ));
        assert!(matches!(
            Rc5Params::new(&[0u8; 256]),
            Err(BlockCipherError::InvalidKeyLength(256))
        ));
    }

    #[test]
    fn rejects_invalid_rounds() {
        assert!(matches!(
            Rc5Params::with_rounds(&[0u8; 8], 256),
            Err(BlockCipherError::InvalidRounds(256))
        ));
    }

    #[test]
    fn new_defaults_to_twelve_rounds() {
        assert_eq!(Rc5Params::new(&[0u8; 8]).unwrap().rounds(), 12);
    }

    #[test]
    fn owns_only_the_supplied_key_as_logical_input() {
        let params = {
            let key = [0xA5; 24];
            Rc5Params::new(&key).unwrap()
        };

        assert_eq!(params.key(), &[0xA5; 24]);
        assert!(params.key[params.key_len..].iter().all(|&byte| byte == 0));
    }
}
