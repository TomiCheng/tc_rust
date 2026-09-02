//! Initial associated-data parameter abstraction.

/// Parameters that provide associated data during AEAD initialization.
///
/// The returned bytes are authenticated but not encrypted. AEAD algorithms
/// may also accept additional associated data incrementally after
/// initialization through their processing interface.
pub trait InitialAadParams {
    /// Returns the initial associated data, which may be empty.
    fn initial_aad(&self) -> &[u8];
}

#[cfg(test)]
mod tests {
    use super::InitialAadParams;

    struct Params<'a> {
        aad: &'a [u8],
    }

    impl InitialAadParams for Params<'_> {
        fn initial_aad(&self) -> &[u8] {
            self.aad
        }
    }

    #[test]
    fn value_is_reachable_through_a_trait_object() {
        let aad = [0x01, 0x02, 0x03];
        let params = Params { aad: &aad };
        let params: &dyn InitialAadParams = &params;

        assert_eq!(params.initial_aad(), aad);
    }

    #[test]
    fn empty_associated_data_is_supported() {
        let params = Params { aad: &[] };
        assert!(params.initial_aad().is_empty());
    }
}
