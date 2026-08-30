//! Validated RC6 initialization parameters.

use core::fmt;

use super::{BlockCipherError, RC6_MAX_KEY_BYTES};

/// Owned, validated RC6 key parameter (variable length).
pub struct Rc6Params {
    key: [u8; RC6_MAX_KEY_BYTES],
    key_len: usize,
}

impl fmt::Debug for Rc6Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rc6Params")
            .field("key_len", &self.key_len)
            .finish()
    }
}

impl Rc6Params {
    /// Validates that `key` is 1..=255 bytes and takes an owned copy.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        if key.is_empty() || key.len() > RC6_MAX_KEY_BYTES {
            return Err(BlockCipherError::InvalidKeyLength(key.len()));
        }

        let mut key_buffer = [0_u8; RC6_MAX_KEY_BYTES];
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
            Rc6Params::new(&[]),
            Err(BlockCipherError::InvalidKeyLength(0))
        ));
        assert!(matches!(
            Rc6Params::new(&[0u8; 256]),
            Err(BlockCipherError::InvalidKeyLength(256))
        ));
    }

    #[test]
    fn debug_redacts_owned_key() {
        let params = Rc6Params::new(&[0xA5u8; 24]).unwrap();
        assert_eq!(format!("{params:?}"), "Rc6Params { key_len: 24 }");
    }

    #[test]
    fn owns_only_the_supplied_key_as_logical_input() {
        let params = {
            let key = [0xA5; 24];
            Rc6Params::new(&key).unwrap()
        };

        assert_eq!(params.key(), &[0xA5; 24]);
        assert!(params.key[params.key_len..].iter().all(|&byte| byte == 0));
    }
}
