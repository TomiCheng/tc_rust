//! Validated SEED initialization parameters.

use core::fmt;

use super::{SEED_KEY_BYTES, SeedError};

/// Owned, validated SEED key parameter (128 bits).
pub struct SeedParams {
    key: [u8; SEED_KEY_BYTES],
}

impl fmt::Debug for SeedParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeedParams")
            .field("key_len", &SEED_KEY_BYTES)
            .finish()
    }
}

impl SeedParams {
    /// Validates that `key` is exactly 16 bytes and takes an owned copy.
    pub fn new(key: &[u8]) -> Result<Self, SeedError> {
        let key: &[u8; SEED_KEY_BYTES] = key
            .try_into()
            .map_err(|_| SeedError::InvalidKeyLength(key.len()))?;
        Ok(Self { key: *key })
    }

    pub(crate) const fn key(&self) -> &[u8; SEED_KEY_BYTES] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_key_length() {
        assert!(matches!(
            SeedParams::new(&[0u8; 15]),
            Err(SeedError::InvalidKeyLength(15))
        ));
    }

    #[test]
    fn debug_redacts_owned_key() {
        let params = SeedParams::new(&[0xA5u8; SEED_KEY_BYTES]).unwrap();
        assert_eq!(alloc::format!("{params:?}"), "SeedParams { key_len: 16 }");
    }
}
