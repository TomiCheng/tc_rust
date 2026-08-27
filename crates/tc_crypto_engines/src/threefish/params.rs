//! Validated Threefish init parameters.

use alloc::vec::Vec;
use core::fmt;

use super::{TWEAK_BYTES, ThreefishBlockSize, ThreefishError};

/// A validated, self-contained Threefish configuration: block size, a matching
/// key, and an optional tweak.
///
/// Constructing one *is* the validation. Because the params carry the block
/// size, [`new`](ThreefishParams::new) can check the key length exactly
/// (`key.len() == block_size.bytes()`), so a `ThreefishParams` is a complete
/// proof of a consistent configuration — there is nothing left for the engine to
/// re-check at `init`; it simply adopts this block size and loads the key.
///
/// A tweak, if present, must be 16 bytes; `None` selects the all-zero tweak
/// (bc's plain `KeyParameter` path).
///
/// The params **own** their material, so one value can be built once, stored, and
/// handed to any number of `init` calls by reference.
pub struct ThreefishParams {
    block_size: ThreefishBlockSize,
    key: Vec<u8>,
    tweak: Option<[u8; TWEAK_BYTES]>,
}

impl fmt::Debug for ThreefishParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreefishParams")
            .field("block_size", &self.block_size)
            .field("key_len", &self.key.len())
            .field("has_tweak", &self.tweak.is_some())
            .finish()
    }
}

impl ThreefishParams {
    /// Validates and copies a key and optional tweak for `block_size`.
    ///
    /// # Errors
    ///
    /// [`ThreefishError::InvalidKeyLength`] if `key` is not exactly
    /// `block_size.bytes()` long, or [`ThreefishError::InvalidTweakLength`] if a
    /// tweak is present but not 16 bytes.
    pub fn new(
        block_size: ThreefishBlockSize,
        key: &[u8],
        tweak: Option<&[u8]>,
    ) -> Result<Self, ThreefishError> {
        // key 長度必須剛好等於分組大小(這是唯一、權威的 key 檢查)。
        if key.len() != block_size.bytes() {
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
            block_size,
            key: key.to_vec(),
            tweak,
        })
    }

    /// The block size this configuration targets.
    pub const fn block_size(&self) -> ThreefishBlockSize {
        self.block_size
    }

    /// The validated key (its length equals `block_size().bytes()`).
    pub(crate) fn key(&self) -> &[u8] {
        &self.key
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
        for size in [
            ThreefishBlockSize::B256,
            ThreefishBlockSize::B512,
            ThreefishBlockSize::B1024,
        ] {
            let p = ThreefishParams::new(size, &zeros[..size.bytes()], None).unwrap();
            assert_eq!(p.block_size(), size);
            assert_eq!(p.key().len(), size.bytes());
            assert_eq!(p.tweak(), None);
        }
    }

    #[test]
    fn accepts_16_byte_tweak() {
        let key = [0u8; 32];
        let tweak = [0u8; 16];
        let p = ThreefishParams::new(ThreefishBlockSize::B256, &key, Some(&tweak)).unwrap();
        assert_eq!(p.tweak().unwrap().len(), 16);
    }

    #[test]
    fn rejects_key_not_matching_block_size() {
        // 32-byte key 對 B512(需 64)→ 錯。
        let key = [0u8; 32];
        assert!(matches!(
            ThreefishParams::new(ThreefishBlockSize::B512, &key, None),
            Err(ThreefishError::InvalidKeyLength(32))
        ));
    }

    #[test]
    fn rejects_bad_tweak_length() {
        let key = [0u8; 64];
        let tweak = [0u8; 8];
        assert!(matches!(
            ThreefishParams::new(ThreefishBlockSize::B512, &key, Some(&tweak)),
            Err(ThreefishError::InvalidTweakLength(8))
        ));
    }

    // 擁有式:建一次後可存、可多次借出(無 lifetime 綁著來源)。
    #[test]
    fn owned_is_storable_and_reusable() {
        let params = {
            let key = [0x11u8; 32];
            ThreefishParams::new(ThreefishBlockSize::B256, &key, None).unwrap()
        }; // key 原陣列已離開作用域,params 仍持有自己的拷貝
        assert_eq!(params.key().len(), 32);
        let _again = params.key();
        let _again2 = params.key();
    }

    #[test]
    fn debug_redacts_key_and_tweak_material() {
        let key = [0xA5u8; 32];
        let tweak = [0x5Au8; 16];
        let params = ThreefishParams::new(ThreefishBlockSize::B256, &key, Some(&tweak)).unwrap();

        assert_eq!(
            alloc::format!("{params:?}"),
            "ThreefishParams { block_size: B256, key_len: 32, has_tweak: true }"
        );
    }
}
