//! Validated RC2 initialization parameters.

use alloc::vec::Vec;
use core::fmt;

use super::{RC2_MAX_EFFECTIVE_KEY_BITS, RC2_MAX_KEY_BYTES, BlockCipherError};

/// Owned, validated RC2 key and effective-key-size parameters.
pub struct Rc2Params {
    key: Vec<u8>,
    effective_key_bits: usize,
}

impl fmt::Debug for Rc2Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rc2Params")
            .field("key_len", &self.key.len())
            .field("effective_key_bits", &self.effective_key_bits)
            .finish()
    }
}

impl Rc2Params {
    /// Validates `key` and takes its effective key size to be the full key length.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        Self::with_effective_key_bits(key, key.len() * 8)
    }

    /// Validates `key` and a separate effective key size in bits (RFC 2268).
    pub fn with_effective_key_bits(key: &[u8], effective_key_bits: usize) -> Result<Self, BlockCipherError> {
        if key.is_empty() || key.len() > RC2_MAX_KEY_BYTES {
            return Err(BlockCipherError::InvalidKeyLength(key.len()));
        }
        if effective_key_bits == 0 || effective_key_bits > RC2_MAX_EFFECTIVE_KEY_BITS {
            return Err(BlockCipherError::InvalidEffectiveKeyBits(effective_key_bits));
        }
        Ok(Self {
            key: key.to_vec(),
            effective_key_bits,
        })
    }

    /// The effective key size in bits.
    pub const fn effective_key_bits(&self) -> usize {
        self.effective_key_bits
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
            Rc2Params::new(&[]),
            Err(BlockCipherError::InvalidKeyLength(0))
        ));
        assert!(matches!(
            Rc2Params::new(&[0u8; 129]),
            Err(BlockCipherError::InvalidKeyLength(129))
        ));
    }

    #[test]
    fn rejects_invalid_effective_bits() {
        assert!(matches!(
            Rc2Params::with_effective_key_bits(&[0u8; 8], 0),
            Err(BlockCipherError::InvalidEffectiveKeyBits(0))
        ));
        assert!(matches!(
            Rc2Params::with_effective_key_bits(&[0u8; 8], 1025),
            Err(BlockCipherError::InvalidEffectiveKeyBits(1025))
        ));
    }

    #[test]
    fn new_defaults_effective_bits_to_key_length() {
        let params = Rc2Params::new(&[0u8; 8]).unwrap();
        assert_eq!(params.effective_key_bits(), 64);
    }
}
