//! Validated Threefish init parameters.

use core::fmt;

use super::{TWEAK_BYTES, ThreefishError};

enum ThreefishKey {
    Threefish256([u8; 32]),
    Threefish512([u8; 64]),
    Threefish1024([u8; 128]),
}

impl ThreefishKey {
    const fn len(&self) -> usize {
        match self {
            Self::Threefish256(_) => 32,
            Self::Threefish512(_) => 64,
            Self::Threefish1024(_) => 128,
        }
    }

    const fn as_slice(&self) -> &[u8] {
        match self {
            Self::Threefish256(key) => key,
            Self::Threefish512(key) => key,
            Self::Threefish1024(key) => key,
        }
    }
}

/// A validated, self-contained Threefish key and optional tweak.
///
/// The key length uniquely selects Threefish-256, Threefish-512, or
/// Threefish-1024 because Threefish keys and blocks always have the same size.
///
/// A tweak, if present, must be 16 bytes; `None` selects the all-zero tweak
/// (bc's plain `KeyParameter` path).
///
/// The params **own** their material, so one value can be built once, stored, and
/// handed to any number of `init` calls by reference.
pub struct ThreefishParams {
    key: ThreefishKey,
    tweak: Option<[u8; TWEAK_BYTES]>,
}

impl fmt::Debug for ThreefishParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreefishParams")
            .field("key_len", &self.key.len())
            .field("has_tweak", &self.tweak.is_some())
            .finish()
    }
}

impl ThreefishParams {
    /// Copies and validates a 256-, 512-, or 1024-bit key and optional tweak.
    ///
    /// # Errors
    ///
    /// [`ThreefishError::InvalidKeyLength`] if `key` is not 32, 64, or 128
    /// bytes, or [`ThreefishError::InvalidTweakLength`] if a tweak is present
    /// but not 16 bytes.
    pub fn new(key: &[u8], tweak: Option<&[u8]>) -> Result<Self, ThreefishError> {
        let key = match key.len() {
            32 => ThreefishKey::Threefish256(key.try_into().unwrap()),
            64 => ThreefishKey::Threefish512(key.try_into().unwrap()),
            128 => ThreefishKey::Threefish1024(key.try_into().unwrap()),
            length => return Err(ThreefishError::InvalidKeyLength(length)),
        };
        // tweak 若給,固定 16 bytes;不給則採全零 tweak。
        let tweak = match tweak {
            Some(t) => {
                if t.len() != TWEAK_BYTES {
                    return Err(ThreefishError::InvalidTweakLength(t.len()));
                }
                let mut arr = [0u8; TWEAK_BYTES];
                arr.copy_from_slice(t);
                Some(arr)
            }
            None => None,
        };
        Ok(ThreefishParams { key, tweak })
    }

    /// Returns the key size in bytes, which is also the Threefish block size.
    pub const fn key_len(&self) -> usize {
        self.key.len()
    }

    /// The validated key.
    pub(crate) const fn key(&self) -> &[u8] {
        self.key.as_slice()
    }

    /// The validated tweak, or `None` for the all-zero tweak.
    pub(crate) fn tweak(&self) -> Option<&[u8]> {
        self.tweak.as_ref().map(|t| t.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_matching_key_for_each_size() {
        let zeros = [0u8; 128];
        for size in [32, 64, 128] {
            let p = ThreefishParams::new(&zeros[..size], None).unwrap();
            assert_eq!(p.key_len(), size);
            assert_eq!(p.key().len(), size);
            assert_eq!(p.tweak(), None);
        }
    }

    #[test]
    fn accepts_16_byte_tweak() {
        let key = [0u8; 32];
        let tweak = [0u8; 16];
        let p = ThreefishParams::new(&key, Some(&tweak)).unwrap();
        assert_eq!(p.tweak().unwrap().len(), 16);
    }

    #[test]
    fn rejects_invalid_key_lengths() {
        for length in [0, 31, 33, 63, 65, 127, 129] {
            assert!(matches!(
                ThreefishParams::new(&alloc::vec![0u8; length], None),
                Err(ThreefishError::InvalidKeyLength(n)) if n == length
            ));
        }
    }

    #[test]
    fn rejects_bad_tweak_length() {
        let key = [0u8; 64];
        let tweak = [0u8; 8];
        assert!(matches!(
            ThreefishParams::new(&key, Some(&tweak)),
            Err(ThreefishError::InvalidTweakLength(8))
        ));
    }

    // 擁有式:建一次後可存、可多次借出(無 lifetime 綁著來源)。
    #[test]
    fn owned_is_storable_and_reusable() {
        let params = {
            let key = [0x11u8; 32];
            ThreefishParams::new(&key, None).unwrap()
        }; // key 原陣列已離開作用域,params 仍持有自己的拷貝
        assert_eq!(params.key().len(), 32);
        let _again = params.key();
        let _again2 = params.key();
    }

    #[test]
    fn debug_redacts_key_and_tweak_material() {
        let key = [0xA5u8; 32];
        let tweak = [0x5Au8; 16];
        let params = ThreefishParams::new(&key, Some(&tweak)).unwrap();

        assert_eq!(
            alloc::format!("{params:?}"),
            "ThreefishParams { key_len: 32, has_tweak: true }"
        );
    }
}
