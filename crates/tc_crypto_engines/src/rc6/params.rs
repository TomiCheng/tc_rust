//! Validated RC6 initialization parameters.

use alloc::vec::Vec;
use core::fmt;

use super::{RC6_MAX_KEY_BYTES, Rc6Error};

/// Owned, validated RC6 key parameter (variable length).
pub struct Rc6Params {
    key: Vec<u8>,
}

impl fmt::Debug for Rc6Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rc6Params")
            .field("key_len", &self.key.len())
            .finish()
    }
}

impl Rc6Params {
    /// Validates that `key` is 1..=255 bytes and takes an owned copy.
    pub fn new(key: &[u8]) -> Result<Self, Rc6Error> {
        if key.is_empty() || key.len() > RC6_MAX_KEY_BYTES {
            return Err(Rc6Error::InvalidKeyLength(key.len()));
        }
        Ok(Self { key: key.to_vec() })
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
            Rc6Params::new(&[]),
            Err(Rc6Error::InvalidKeyLength(0))
        ));
        assert!(matches!(
            Rc6Params::new(&[0u8; 256]),
            Err(Rc6Error::InvalidKeyLength(256))
        ));
    }

    #[test]
    fn debug_redacts_owned_key() {
        let params = Rc6Params::new(&[0xA5u8; 24]).unwrap();
        assert_eq!(alloc::format!("{params:?}"), "Rc6Params { key_len: 24 }");
    }
}
