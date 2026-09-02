//! Convenience ChaCha AEAD parameters.

use core::fmt;

use tc_params::{InitialAadParams, IvParams, KeyParams};

/// Borrowed ChaCha AEAD initialization parameters.
///
/// This type does not copy or validate its inputs. The selected engine
/// validates the key and nonce lengths during initialization. Callers may
/// instead implement the parameter traits on their own types.
#[derive(Clone, Copy)]
pub struct Params<'a> {
    key: &'a [u8],
    nonce: &'a [u8],
    initial_aad: &'a [u8],
}

impl<'a> Params<'a> {
    /// Borrows a key, nonce, and initial associated data.
    pub const fn new(key: &'a [u8], nonce: &'a [u8], initial_aad: &'a [u8]) -> Self {
        Self {
            key,
            nonce,
            initial_aad,
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

impl fmt::Debug for Params<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Params")
            .field("key_len", &self.key.len())
            .field("nonce_len", &self.nonce.len())
            .field("initial_aad_len", &self.initial_aad.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::*;

    #[test]
    fn exposes_all_borrowed_values() {
        let params = Params::new(&[1, 2], &[3, 4, 5], &[6]);
        assert_eq!(params.key(), &[1, 2]);
        assert_eq!(params.iv(), &[3, 4, 5]);
        assert_eq!(params.initial_aad(), &[6]);
    }

    #[test]
    fn debug_redacts_parameter_bytes() {
        let params = Params::new(&[0xaa; 32], &[0xbb; 12], &[0xcc; 3]);
        assert_eq!(
            format!("{params:?}"),
            "Params { key_len: 32, nonce_len: 12, initial_aad_len: 3 }"
        );
    }
}
