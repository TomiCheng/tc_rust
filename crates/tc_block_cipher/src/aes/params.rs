//! Validated AES initialization parameters.

use core::fmt;

use super::BlockCipherError;

enum AesKey {
    Aes128([u8; 16]),
    Aes192([u8; 24]),
    Aes256([u8; 32]),
}

/// Owned, validated AES key parameters.
pub struct AesParams {
    key: AesKey,
}

impl AesParams {
    /// Copies and validates a 128-, 192-, or 256-bit AES key.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        let key = match key.len() {
            16 => AesKey::Aes128(key.try_into().unwrap()),
            24 => AesKey::Aes192(key.try_into().unwrap()),
            32 => AesKey::Aes256(key.try_into().unwrap()),
            length => return Err(BlockCipherError::InvalidKeyLength(length)),
        };
        Ok(Self { key })
    }

    /// Returns the AES key size in bytes without exposing the key material.
    pub const fn key_len(&self) -> usize {
        match self.key {
            AesKey::Aes128(_) => 16,
            AesKey::Aes192(_) => 24,
            AesKey::Aes256(_) => 32,
        }
    }

    pub(crate) const fn key(&self) -> &[u8] {
        match &self.key {
            AesKey::Aes128(key) => key,
            AesKey::Aes192(key) => key,
            AesKey::Aes256(key) => key,
        }
    }
}

impl fmt::Debug for AesParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesParams")
            .field("key_len", &self.key_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_standard_key_lengths() {
        for length in [16, 24, 32] {
            assert_eq!(
                AesParams::new(&alloc::vec![0u8; length]).unwrap().key_len(),
                length
            );
        }
        for length in [0, 15, 17, 23, 25, 31, 33] {
            assert!(matches!(
                AesParams::new(&alloc::vec![0u8; length]),
                Err(BlockCipherError::InvalidKeyLength(n)) if n == length
            ));
        }
    }

    #[test]
    fn owns_and_redacts_key_material() {
        let params = {
            let key = [0xA5u8; 24];
            AesParams::new(&key).unwrap()
        };
        assert_eq!(params.key(), &[0xA5u8; 24]);
        assert_eq!(alloc::format!("{params:?}"), "AesParams { key_len: 24 }");
    }
}
