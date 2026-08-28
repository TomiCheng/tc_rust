//! Validated SKIPJACK initialization parameters.

use core::fmt;

use super::{SKIPJACK_KEY_BYTES, SkipjackError};

/// Owned, validated SKIPJACK key parameter (80 bits).
pub struct SkipjackParams {
    key: [u8; SKIPJACK_KEY_BYTES],
}

impl fmt::Debug for SkipjackParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SkipjackParams")
            .field("key_len", &SKIPJACK_KEY_BYTES)
            .finish()
    }
}

impl SkipjackParams {
    /// Validates that `key` is exactly 10 bytes and takes an owned copy.
    pub fn new(key: &[u8]) -> Result<Self, SkipjackError> {
        let key: &[u8; SKIPJACK_KEY_BYTES] = key
            .try_into()
            .map_err(|_| SkipjackError::InvalidKeyLength(key.len()))?;
        Ok(Self { key: *key })
    }

    pub(crate) const fn key(&self) -> &[u8; SKIPJACK_KEY_BYTES] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_key_length() {
        assert!(matches!(
            SkipjackParams::new(&[0u8; 9]),
            Err(SkipjackError::InvalidKeyLength(9))
        ));
        assert!(matches!(
            SkipjackParams::new(&[0u8; 16]),
            Err(SkipjackError::InvalidKeyLength(16))
        ));
    }

    #[test]
    fn debug_redacts_owned_key() {
        let params = SkipjackParams::new(&[0xA5u8; SKIPJACK_KEY_BYTES]).unwrap();
        assert_eq!(
            alloc::format!("{params:?}"),
            "SkipjackParams { key_len: 10 }"
        );
    }
}
