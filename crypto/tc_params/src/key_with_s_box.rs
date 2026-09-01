//! Key-with-S-box parameter abstraction.

use crate::KeyParams;

/// Parameters that provide an S-box alongside key material.
///
/// Like [`KeyParams::key`], this hands over bytes and leaves checking them to
/// whatever consumes them. Which tables are valid, and which one a bare key
/// should fall back to, are properties of the algorithm, so neither is decided
/// here.
pub trait KeyWithSBoxParams: KeyParams {
    /// Returns the S-box bytes.
    fn s_box(&self) -> &[u8];
}

#[cfg(test)]
mod tests {
    use super::{KeyParams, KeyWithSBoxParams};

    struct KeyAndSBox<'a> {
        key: &'a [u8],
        s_box: &'a [u8],
    }

    impl KeyParams for KeyAndSBox<'_> {
        fn key(&self) -> &[u8] {
            self.key
        }
    }

    impl KeyWithSBoxParams for KeyAndSBox<'_> {
        fn s_box(&self) -> &[u8] {
            self.s_box
        }
    }

    #[test]
    fn both_halves_are_reachable_through_a_trait_object() {
        let key = [0x01_u8, 0x02, 0x03];
        let table = [0x0a_u8, 0x0b];
        let params = KeyAndSBox {
            key: &key,
            s_box: &table,
        };

        let params: &dyn KeyWithSBoxParams = &params;
        assert_eq!(params.key(), &key);
        assert_eq!(params.s_box(), &table);
    }
}
