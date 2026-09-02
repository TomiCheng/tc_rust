//! Tweak parameter abstraction.

/// Parameters that optionally provide tweak bytes.
///
/// The consuming algorithm defines the tweak length and the meaning of no
/// tweak. Implementations only expose the caller's value.
pub trait TweakParams {
    /// Returns the tweak bytes, or `None` when the algorithm's default applies.
    fn tweak(&self) -> Option<&[u8]>;
}

#[cfg(test)]
mod tests {
    use super::TweakParams;

    struct Params<'a> {
        tweak: Option<&'a [u8]>,
    }

    impl TweakParams for Params<'_> {
        fn tweak(&self) -> Option<&[u8]> {
            self.tweak
        }
    }

    #[test]
    fn value_is_reachable_through_a_trait_object() {
        let tweak = [0x03_u8, 0x04];
        let params = Params {
            tweak: Some(&tweak),
        };
        let params: &dyn TweakParams = &params;

        assert_eq!(params.tweak(), Some(tweak.as_slice()));
    }

    #[test]
    fn an_absent_tweak_is_preserved() {
        let params = Params { tweak: None };
        assert_eq!(params.tweak(), None);
    }
}
