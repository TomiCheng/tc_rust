//! RC5 parameter abstraction.

use crate::KeyParams;

/// Parameters that provide an RC5 key and round count.
///
/// Implementations only expose parameter values. The RC5 engine is responsible
/// for validating the key length and round count.
pub trait Rc5Params: KeyParams {
    /// Returns the number of RC5 rounds.
    fn rounds(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::{KeyParams, Rc5Params};

    struct Params<'a> {
        key: &'a [u8],
        rounds: usize,
    }

    impl KeyParams for Params<'_> {
        fn key(&self) -> &[u8] {
            self.key
        }
    }

    impl Rc5Params for Params<'_> {
        fn rounds(&self) -> usize {
            self.rounds
        }
    }

    #[test]
    fn values_are_reachable_through_a_trait_object() {
        let key = [0x01_u8, 0x02, 0x03];
        let params = Params {
            key: &key,
            rounds: 16,
        };

        let params: &dyn Rc5Params = &params;
        assert_eq!(params.key(), &key);
        assert_eq!(params.rounds(), 16);
    }
}
