//! Validated RC5 initialization parameters (shared by both word sizes).

use core::fmt;

use super::{BlockCipherError, RC5_MAX_KEY_BYTES};

/// Owned, validated RC5 key parameter.
///
/// The round count is part of the engine's type, so it is not carried here.
pub struct Rc5Params {
    key: [u8; RC5_MAX_KEY_BYTES],
    key_len: usize,
}

impl fmt::Debug for Rc5Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rc5Params")
            .field("key_len", &self.key_len)
            .finish()
    }
}

impl Rc5Params {
    /// Validates that `key` is 1..=255 bytes and takes an owned copy.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        if key.is_empty() || key.len() > RC5_MAX_KEY_BYTES {
            return Err(BlockCipherError::InvalidKeyLength(key.len()));
        }

        let mut key_buffer = [0_u8; RC5_MAX_KEY_BYTES];
        key_buffer[..key.len()].copy_from_slice(key);

        Ok(Self {
            key: key_buffer,
            key_len: key.len(),
        })
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
    fn owns_only_the_supplied_key_as_logical_input() {
        let params = {
            let key = [0xA5; 24];
            Rc5Params::new(&key).unwrap()
        };

        assert_eq!(params.key(), &[0xA5; 24]);
        assert!(params.key[params.key_len..].iter().all(|&byte| byte == 0));
    }
}
