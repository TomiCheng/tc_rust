//! CAST5 initialization parameters.

use core::fmt;

use super::{BlockCipherError, CAST5_MAX_KEY_BYTES, CAST5_MIN_KEY_BYTES};

/// An owned CAST5 key containing 5 through 16 bytes.
pub struct Cast5Params {
    key: [u8; CAST5_MAX_KEY_BYTES],
    key_len: usize,
}

impl Cast5Params {
    /// Copies and validates a CAST5 key.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        if !(CAST5_MIN_KEY_BYTES..=CAST5_MAX_KEY_BYTES).contains(&key.len()) {
            return Err(BlockCipherError::InvalidKeyLength(key.len()));
        }

        let mut key_buffer = [0_u8; CAST5_MAX_KEY_BYTES];
        key_buffer[..key.len()].copy_from_slice(key);

        Ok(Self {
            key: key_buffer,
            key_len: key.len(),
        })
    }

    /// Returns the key length in bytes without exposing key material.
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }
}

impl fmt::Debug for Cast5Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cast5Params")
            .field("key_len", &self.key_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_standard_key_length_range() {
        for length in 5..=16 {
            assert_eq!(
                Cast5Params::new(&alloc::vec![0u8; length])
                    .unwrap()
                    .key_len(),
                length
            );
        }
        for length in [0, 1, 4, 17, 32] {
            assert!(matches!(
                Cast5Params::new(&alloc::vec![0u8; length]),
                Err(BlockCipherError::InvalidKeyLength(n)) if n == length
            ));
        }
    }

    #[test]
    fn owns_and_redacts_key_material() {
        let params = {
            let key = [0xA5; 12];
            Cast5Params::new(&key).unwrap()
        };
        assert_eq!(params.key(), &[0xA5; 12]);
        assert_eq!(alloc::format!("{params:?}"), "Cast5Params { key_len: 12 }");
    }
}
