//! CAST6 initialization parameters.

use core::fmt;

use super::{BlockCipherError, CAST6_KEY_BYTES};

const KEY_CAPACITY: usize = CAST6_KEY_BYTES[CAST6_KEY_BYTES.len() - 1];

/// An owned CAST6 key with a standard length from 128 through 256 bits.
pub struct Cast6Params {
    key: [u8; KEY_CAPACITY],
    key_len: usize,
}

impl Cast6Params {
    /// Copies and validates a CAST6 key.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        if !CAST6_KEY_BYTES.contains(&key.len()) {
            return Err(BlockCipherError::InvalidKeyLength(key.len()));
        }

        let mut key_buffer = [0_u8; KEY_CAPACITY];
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

impl fmt::Debug for Cast6Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cast6Params")
            .field("key_len", &self.key_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_standard_key_lengths() {
        for length in CAST6_KEY_BYTES {
            assert_eq!(
                Cast6Params::new(&vec![0u8; length])
                    .unwrap()
                    .key_len(),
                length
            );
        }
        for length in [0, 15, 17, 19, 21, 27, 29, 31, 33] {
            assert!(matches!(
                Cast6Params::new(&vec![0u8; length]),
                Err(BlockCipherError::InvalidKeyLength(n)) if n == length
            ));
        }
    }

    #[test]
    fn owns_and_redacts_key_material() {
        let params = {
            let key = [0xA5; 24];
            Cast6Params::new(&key).unwrap()
        };
        assert_eq!(params.key(), &[0xA5; 24]);
        assert_eq!(format!("{params:?}"), "Cast6Params { key_len: 24 }");
    }
}
