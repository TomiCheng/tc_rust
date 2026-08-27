//! Validated Threefish init parameters.

use alloc::vec::Vec;

use super::{ThreefishError, TWEAK_BYTES};

/// Validated key + optional tweak for [`ThreefishEngine`](super::ThreefishEngine).
///
/// Constructing one *is* the validation: [`new`](ThreefishParams::new) rejects a
/// key that is not a legal Threefish size and a tweak that is not 16 bytes, so a
/// `ThreefishParams` value is a proof that its lengths are individually sound.
/// (Whether the key matches a *particular* engine's block size — 256 vs 512 vs
/// 1024 — is the engine's cross-check at `init`, since the params do not know
/// which variant they will drive.)
///
/// The params **own** their material (an owned key plus an optional fixed tweak),
/// so a single value can be built once, stored, and handed to any number of
/// `init` calls by reference; the engine copies it into its own schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreefishParams {
    key: Vec<u8>,
    tweak: Option<[u8; TWEAK_BYTES]>,
}

impl ThreefishParams {
    /// Validates and copies a key and optional tweak into owned storage.
    ///
    /// `key` must be 32, 64 or 128 bytes (Threefish-256 / 512 / 1024). `tweak`,
    /// if present, must be exactly 16 bytes; `None` selects the all-zero tweak
    /// (bc's plain `KeyParameter` path).
    ///
    /// # Errors
    ///
    /// [`ThreefishError::InvalidKeyLength`] or
    /// [`ThreefishError::InvalidTweakLength`] for an unsupported length.
    pub fn new(key: &[u8], tweak: Option<&[u8]>) -> Result<Self, ThreefishError> {
        // key 長度 = 分組大小,合法者為 32 / 64 / 128 bytes。
        if !matches!(key.len(), 32 | 64 | 128) {
            return Err(ThreefishError::InvalidKeyLength(key.len()));
        }
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
        Ok(ThreefishParams {
            key: key.to_vec(),
            tweak,
        })
    }

    /// The validated key (its length equals the intended block size in bytes).
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// The validated tweak, or `None` for the all-zero tweak.
    pub fn tweak(&self) -> Option<&[u8]> {
        self.tweak.as_ref().map(|t| t.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_legal_key_sizes() {
        let zeros = [0u8; 128];
        for len in [32usize, 64, 128] {
            let p = ThreefishParams::new(&zeros[..len], None).unwrap();
            assert_eq!(p.key().len(), len);
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
    fn rejects_bad_key_length() {
        let key = [0u8; 20];
        assert_eq!(
            ThreefishParams::new(&key, None),
            Err(ThreefishError::InvalidKeyLength(20))
        );
    }

    #[test]
    fn rejects_bad_tweak_length() {
        let key = [0u8; 64];
        let tweak = [0u8; 8];
        assert_eq!(
            ThreefishParams::new(&key, Some(&tweak)),
            Err(ThreefishError::InvalidTweakLength(8))
        );
    }

    // 擁有式:建一次後可存、可多次借出(無 lifetime 綁著來源)。
    #[test]
    fn owned_is_storable_and_reusable() {
        let params = {
            let key = [0x11u8; 64];
            ThreefishParams::new(&key, None).unwrap()
        }; // key 原陣列已離開作用域,params 仍持有自己的拷貝
        assert_eq!(params.key().len(), 64);
        let _again = params.key();
        let _again2 = params.key();
    }
}
