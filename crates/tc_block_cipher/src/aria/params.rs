//! ARIA initialization parameters.

use core::fmt;

use super::BlockCipherError;

enum AriaKey {
    Aria128([u8; 16]),
    Aria192([u8; 24]),
    Aria256([u8; 32]),
}

/// An owned ARIA-128, ARIA-192, or ARIA-256 key.
pub struct AriaParams {
    key: AriaKey,
}

impl AriaParams {
    /// Copies a 16-, 24-, or 32-byte ARIA key.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        let key = match key.len() {
            16 => AriaKey::Aria128(key.try_into().unwrap()),
            24 => AriaKey::Aria192(key.try_into().unwrap()),
            32 => AriaKey::Aria256(key.try_into().unwrap()),
            length => return Err(BlockCipherError::InvalidKeyLength(length)),
        };
        Ok(Self { key })
    }

    /// Returns the ARIA key size in bytes without exposing key material.
    pub const fn key_len(&self) -> usize {
        match self.key {
            AriaKey::Aria128(_) => 16,
            AriaKey::Aria192(_) => 24,
            AriaKey::Aria256(_) => 32,
        }
    }

    pub(crate) const fn key(&self) -> &[u8] {
        match &self.key {
            AriaKey::Aria128(key) => key,
            AriaKey::Aria192(key) => key,
            AriaKey::Aria256(key) => key,
        }
    }
}

impl fmt::Debug for AriaParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AriaParams")
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
                AriaParams::new(&alloc::vec![0u8; length])
                    .unwrap()
                    .key_len(),
                length
            );
        }
        for length in [0, 15, 17, 23, 25, 31, 33] {
            assert!(matches!(
                AriaParams::new(&alloc::vec![0u8; length]),
                Err(BlockCipherError::InvalidKeyLength(n)) if n == length
            ));
        }
    }

    #[test]
    fn owns_and_redacts_key_material() {
        let params = {
            let key = [0xA5; 24];
            AriaParams::new(&key).unwrap()
        };
        assert_eq!(params.key(), &[0xA5; 24]);
        assert_eq!(alloc::format!("{params:?}"), "AriaParams { key_len: 24 }");
    }
}
