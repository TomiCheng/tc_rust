//! Convenience parameters for AEAD block-cipher constructions.

use core::fmt;

use crate::{InitialAadParams, IvParams, KeyParams, MacSizeParams};

/// Borrowed key, nonce, initial AAD, and authentication-tag size parameters.
///
/// This type does not validate any value. The consuming AEAD construction
/// owns all key, nonce, and authentication-tag length policy.
#[derive(Clone, Copy)]
pub struct AeadBlockParams<'a> {
    key: &'a [u8],
    nonce: &'a [u8],
    initial_aad: &'a [u8],
    mac_size: usize,
}

impl<'a> AeadBlockParams<'a> {
    /// Borrows all byte slices and selects a MAC size in bytes.
    pub const fn new(
        key: &'a [u8],
        nonce: &'a [u8],
        mac_size: usize,
        initial_aad: &'a [u8],
    ) -> Self {
        Self {
            key,
            nonce,
            initial_aad,
            mac_size,
        }
    }
}

impl KeyParams for AeadBlockParams<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl IvParams for AeadBlockParams<'_> {
    fn iv(&self) -> &[u8] {
        self.nonce
    }
}

impl InitialAadParams for AeadBlockParams<'_> {
    fn initial_aad(&self) -> &[u8] {
        self.initial_aad
    }
}

impl MacSizeParams for AeadBlockParams<'_> {
    fn mac_size(&self) -> usize {
        self.mac_size
    }
}

impl fmt::Debug for AeadBlockParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadBlockParams")
            .field("key_len", &self.key.len())
            .field("nonce_len", &self.nonce.len())
            .field("initial_aad_len", &self.initial_aad.len())
            .field("mac_size", &self.mac_size)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::*;

    #[test]
    fn exposes_each_trait_and_redacts_byte_values() {
        let params = AeadBlockParams::new(&[1, 2], &[3, 4, 5], 12, &[6]);

        assert_eq!((&params as &dyn KeyParams).key(), &[1, 2]);
        assert_eq!((&params as &dyn IvParams).iv(), &[3, 4, 5]);
        assert_eq!((&params as &dyn InitialAadParams).initial_aad(), &[6]);
        assert_eq!((&params as &dyn MacSizeParams).mac_size(), 12);
        assert_eq!(
            format!("{params:?}"),
            "AeadBlockParams { key_len: 2, nonce_len: 3, initial_aad_len: 1, mac_size: 12 }"
        );
    }
}
