//! Convenience CCM parameters.

use core::fmt;

use tc_params::{InitialAadParams, IvParams, KeyParams, MacSizeParams};

/// Borrowed CCM initialization parameters.
///
/// The MAC size is expressed in bytes. CCM accepts the even sizes from 4
/// through 16 bytes. The selected engine validates all lengths during
/// initialization.
#[derive(Clone, Copy)]
pub struct Params<'a> {
    key: &'a [u8],
    nonce: &'a [u8],
    initial_aad: &'a [u8],
    mac_size: usize,
}

impl<'a> Params<'a> {
    /// Borrows a key, nonce, and initial AAD and selects a MAC size in bytes.
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

impl KeyParams for Params<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl IvParams for Params<'_> {
    fn iv(&self) -> &[u8] {
        self.nonce
    }
}

impl InitialAadParams for Params<'_> {
    fn initial_aad(&self) -> &[u8] {
        self.initial_aad
    }
}

impl MacSizeParams for Params<'_> {
    fn mac_size(&self) -> usize {
        self.mac_size
    }
}

impl fmt::Debug for Params<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Params")
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
    fn exposes_all_parameter_values_and_redacts_bytes() {
        let params = Params::new(&[1, 2], &[3, 4, 5], 12, &[6]);
        assert_eq!(params.key(), &[1, 2]);
        assert_eq!(params.iv(), &[3, 4, 5]);
        assert_eq!(params.initial_aad(), &[6]);
        assert_eq!(params.mac_size(), 12);
        assert_eq!(
            format!("{params:?}"),
            "Params { key_len: 2, nonce_len: 3, initial_aad_len: 1, mac_size: 12 }"
        );
    }
}
