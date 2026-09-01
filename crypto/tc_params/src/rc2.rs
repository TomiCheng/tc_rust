//! RC2 parameter abstraction.

use crate::KeyParams;

/// Parameters that provide an RC2 key and its effective size in bits.
///
/// Implementations only expose parameter values. The RC2 engine is responsible
/// for validating the key length and effective key size.
pub trait Rc2Params: KeyParams {
    /// Returns the effective key size in bits.
    fn effective_key_bits(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::{KeyParams, Rc2Params};

    struct Params<'a> {
        key: &'a [u8],
        effective_key_bits: usize,
    }

    impl KeyParams for Params<'_> {
        fn key(&self) -> &[u8] {
            self.key
        }
    }

    impl Rc2Params for Params<'_> {
        fn effective_key_bits(&self) -> usize {
            self.effective_key_bits
        }
    }

    #[test]
    fn values_are_reachable_through_a_trait_object() {
        let key = [0x01_u8, 0x02, 0x03];
        let params = Params {
            key: &key,
            effective_key_bits: 17,
        };

        let params: &dyn Rc2Params = &params;
        assert_eq!(params.key(), &key);
        assert_eq!(params.effective_key_bits(), 17);
    }
}
