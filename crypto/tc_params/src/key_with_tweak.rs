//! Key-with-tweak parameter abstraction.

use crate::KeyParams;

/// Parameters that optionally provide a tweak alongside key material.
///
/// The consuming algorithm defines the tweak length and the meaning of no
/// tweak. Implementations only expose the caller's values.
pub trait KeyWithTweakParams: KeyParams {
    /// Returns the tweak bytes, or `None` when the algorithm's default applies.
    fn tweak(&self) -> Option<&[u8]>;
}

#[cfg(test)]
mod tests {
    use super::{KeyParams, KeyWithTweakParams};

    struct KeyAndTweak<'a> {
        key: &'a [u8],
        tweak: Option<&'a [u8]>,
    }

    impl KeyParams for KeyAndTweak<'_> {
        fn key(&self) -> &[u8] {
            self.key
        }
    }

    impl KeyWithTweakParams for KeyAndTweak<'_> {
        fn tweak(&self) -> Option<&[u8]> {
            self.tweak
        }
    }

    #[test]
    fn values_are_reachable_through_a_trait_object() {
        let key = [0x01_u8, 0x02];
        let tweak = [0x03_u8, 0x04];
        let params = KeyAndTweak {
            key: &key,
            tweak: Some(&tweak),
        };

        let params: &dyn KeyWithTweakParams = &params;
        assert_eq!(params.key(), &key);
        assert_eq!(params.tweak(), Some(tweak.as_slice()));
    }

    #[test]
    fn an_absent_tweak_is_preserved() {
        let params = KeyAndTweak {
            key: &[0x01],
            tweak: None,
        };
        assert_eq!(params.tweak(), None);
    }
}
