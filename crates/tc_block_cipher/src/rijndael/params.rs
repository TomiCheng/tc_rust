//! Validated Rijndael initialization parameters.

use core::fmt;

use super::{BlockCipherError, RIJNDAEL_KEY_BYTES};

const KEY_CAPACITY: usize = RIJNDAEL_KEY_BYTES[RIJNDAEL_KEY_BYTES.len() - 1];

/// Owned, validated Rijndael key parameter (16/20/24/28/32 bytes).
pub struct RijndaelParams {
    key: [u8; KEY_CAPACITY],
    key_len: usize,
}

impl fmt::Debug for RijndaelParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RijndaelParams")
            .field("key_len", &self.key_len)
            .finish()
    }
}

impl RijndaelParams {
    /// Validates that `key` is a legal Rijndael key length and takes an owned copy.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        if !RIJNDAEL_KEY_BYTES.contains(&key.len()) {
            return Err(BlockCipherError::InvalidKeyLength(key.len()));
        }

        let mut key_buffer = [0_u8; KEY_CAPACITY];
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
            RijndaelParams::new(&[0u8; 17]),
            Err(BlockCipherError::InvalidKeyLength(17))
        ));
    }

    #[test]
    fn accepts_all_legal_lengths() {
        for len in RIJNDAEL_KEY_BYTES {
            assert!(RijndaelParams::new(&alloc::vec![0u8; len]).is_ok());
        }
    }

    #[test]
    fn debug_redacts_owned_key() {
        let params = RijndaelParams::new(&[0xA5u8; 24]).unwrap();
        assert_eq!(
            alloc::format!("{params:?}"),
            "RijndaelParams { key_len: 24 }"
        );
    }

    #[test]
    fn owns_only_the_supplied_key_as_logical_input() {
        let params = {
            let key = [0xA5; 20];
            RijndaelParams::new(&key).unwrap()
        };

        assert_eq!(params.key(), &[0xA5; 20]);
        assert!(params.key[params.key_len..].iter().all(|&byte| byte == 0));
    }
}
