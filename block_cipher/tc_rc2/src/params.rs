//! Convenience implementation of [`Rc2Params`].

use core::fmt;

use tc_block_cipher::KeyParams;

use crate::{MAX_EFFECTIVE_KEY_BITS, MAX_KEY_BYTES};

/// Supplies an RC2 key and its effective size.
///
/// Timing is implementation-defined; implementations should return the
/// borrowed key and public size without secret-dependent work.
pub trait Rc2Params: KeyParams {
    /// Returns the effective key size in bits. Timing is implementation-defined.
    fn effective_key_bits(&self) -> usize;
}

/// Borrowed RC2 key and effective-key-size parameters.
///
/// This type does not validate either value; [`Rc2Engine`](crate::Rc2Engine)
/// performs validation when it is initialized. Callers with their own parameter
/// type can implement [`Rc2Params`] directly.
/// Constant time with respect to key contents; key length and effective size are public.
#[derive(Clone, Copy)]
pub struct Params<'a> {
    key: &'a [u8],
    effective_key_bits: usize,
}

impl<'a> Params<'a> {
    /// Uses the full supplied key as the effective key.
    ///
    /// As in Bouncy Castle, a key longer than RC2's maximum defaults to 1024
    /// effective bits; the engine will still reject that key's byte length.
    /// Constant time with respect to key contents; key length is public.
    pub const fn new(key: &'a [u8]) -> Self {
        let effective_key_bits = if key.len() > MAX_KEY_BYTES {
            MAX_EFFECTIVE_KEY_BITS
        } else {
            key.len() * 8
        };
        Self {
            key,
            effective_key_bits,
        }
    }

    /// Uses an explicit effective key size in bits. Constant time.
    pub const fn with_effective_key_bits(key: &'a [u8], effective_key_bits: usize) -> Self {
        Self {
            key,
            effective_key_bits,
        }
    }
}

impl KeyParams for Params<'_> {
    /// Borrows the key without inspecting it. Constant time.
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl Rc2Params for Params<'_> {
    /// Returns the stored public size. Constant time.
    fn effective_key_bits(&self) -> usize {
        self.effective_key_bits
    }
}

impl fmt::Debug for Params<'_> {
    /// Writes public lengths and parameters without revealing key bytes.
    /// Constant time with respect to the key; output timing depends on the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Params")
            .field("key_len", &self.key.len())
            .field("effective_key_bits", &self.effective_key_bits)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::*;

    #[test]
    fn defaults_to_the_full_key_size() {
        let params = Params::new(&[0u8; 8]);
        assert_eq!(params.key(), &[0u8; 8]);
        assert_eq!(params.effective_key_bits(), 64);
    }

    #[test]
    fn accepts_an_explicit_effective_key_size_without_validation() {
        let params = Params::with_effective_key_bits(&[], 0);
        assert_eq!(params.key(), &[] as &[u8]);
        assert_eq!(params.effective_key_bits(), 0);
    }

    #[test]
    fn debug_redacts_the_key() {
        let params = Params::with_effective_key_bits(&[0xff; 8], 40);
        assert_eq!(
            format!("{params:?}"),
            "Params { key_len: 8, effective_key_bits: 40 }"
        );
    }
}
