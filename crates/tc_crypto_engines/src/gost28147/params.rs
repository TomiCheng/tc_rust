//! Validated GOST 28147 initialization parameters.

use core::fmt;

use super::{GOST28147_KEY_BYTES, GOST28147_S_BOX_BYTES, BlockCipherError, Gost28147SBox};

/// Owned, validated GOST 28147 key and S-box parameters.
pub struct Gost28147Params {
    key: [u8; GOST28147_KEY_BYTES],
    s_box: [u8; GOST28147_S_BOX_BYTES],
    s_box_name: Option<Gost28147SBox>,
}

impl fmt::Debug for Gost28147Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gost28147Params")
            .field("key_len", &GOST28147_KEY_BYTES)
            .field(
                "s_box",
                &self.s_box_name.map(Gost28147SBox::name).unwrap_or("Custom"),
            )
            .finish()
    }
}

impl Gost28147Params {
    /// Validates `key` and selects Bouncy Castle's default S-box.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        Self::with_s_box(key, Gost28147SBox::Default)
    }

    /// Validates `key` and selects a standardized S-box.
    pub fn with_s_box(key: &[u8], s_box: Gost28147SBox) -> Result<Self, BlockCipherError> {
        Ok(Self {
            key: validate_key(key)?,
            s_box: *s_box.table(),
            s_box_name: Some(s_box),
        })
    }

    /// Validates `key` and a custom 8-by-16 nibble S-box.
    pub fn with_custom_s_box(key: &[u8], s_box: &[u8]) -> Result<Self, BlockCipherError> {
        let key = validate_key(key)?;
        let s_box = validate_s_box(s_box)?;
        Ok(Self {
            key,
            s_box,
            s_box_name: None,
        })
    }

    /// The selected standardized S-box, or `None` for a custom table.
    pub const fn s_box_name(&self) -> Option<Gost28147SBox> {
        self.s_box_name
    }

    pub(crate) const fn key(&self) -> &[u8; GOST28147_KEY_BYTES] {
        &self.key
    }

    pub(crate) const fn s_box(&self) -> &[u8; GOST28147_S_BOX_BYTES] {
        &self.s_box
    }
}

fn validate_key(key: &[u8]) -> Result<[u8; GOST28147_KEY_BYTES], BlockCipherError> {
    let key: &[u8; GOST28147_KEY_BYTES] = key
        .try_into()
        .map_err(|_| BlockCipherError::InvalidKeyLength(key.len()))?;
    Ok(*key)
}

fn validate_s_box(s_box: &[u8]) -> Result<[u8; GOST28147_S_BOX_BYTES], BlockCipherError> {
    let s_box: &[u8; GOST28147_S_BOX_BYTES] = s_box
        .try_into()
        .map_err(|_| BlockCipherError::InvalidSBoxLength(s_box.len()))?;

    for (row_index, row) in s_box.chunks_exact(16).enumerate() {
        let mut seen = 0u16;
        for (column, &value) in row.iter().enumerate() {
            if value > 15 {
                return Err(BlockCipherError::InvalidSBoxValue {
                    index: row_index * 16 + column,
                    value,
                });
            }
            let bit = 1u16 << value;
            if seen & bit != 0 {
                return Err(BlockCipherError::InvalidSBoxRow(row_index));
            }
            seen |= bit;
        }
        if seen != u16::MAX {
            return Err(BlockCipherError::InvalidSBoxRow(row_index));
        }
    }

    Ok(*s_box)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_key_length() {
        assert!(matches!(
            Gost28147Params::new(&[0u8; 31]),
            Err(BlockCipherError::InvalidKeyLength(31))
        ));
    }

    #[test]
    fn validates_custom_s_box_shape() {
        let key = [0u8; GOST28147_KEY_BYTES];
        assert!(matches!(
            Gost28147Params::with_custom_s_box(&key, &[0u8; 127]),
            Err(BlockCipherError::InvalidSBoxLength(127))
        ));

        let mut bad_value = *Gost28147SBox::Default.table();
        bad_value[17] = 16;
        assert!(matches!(
            Gost28147Params::with_custom_s_box(&key, &bad_value),
            Err(BlockCipherError::InvalidSBoxValue {
                index: 17,
                value: 16
            })
        ));

        let mut duplicate = *Gost28147SBox::Default.table();
        duplicate[1] = duplicate[0];
        assert!(matches!(
            Gost28147Params::with_custom_s_box(&key, &duplicate),
            Err(BlockCipherError::InvalidSBoxRow(0))
        ));
    }

    #[test]
    fn debug_redacts_owned_material() {
        let key = [0xA5u8; GOST28147_KEY_BYTES];
        let params = Gost28147Params::with_s_box(&key, Gost28147SBox::DigestA).unwrap();
        assert_eq!(
            alloc::format!("{params:?}"),
            "Gost28147Params { key_len: 32, s_box: \"D-A\" }"
        );
    }

    #[test]
    fn owned_material_outlives_inputs() {
        let params = {
            let key = [0x11u8; GOST28147_KEY_BYTES];
            let s_box = *Gost28147SBox::DigestA.table();
            Gost28147Params::with_custom_s_box(&key, &s_box).unwrap()
        };

        assert_eq!(params.key(), &[0x11u8; GOST28147_KEY_BYTES]);
        assert_eq!(params.s_box_name(), None);
    }
}
