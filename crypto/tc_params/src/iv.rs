//! Initialization-vector parameter abstraction.

/// Parameters that provide an initialization vector.
///
/// Implementations only expose the caller's value. The consuming mode or
/// algorithm defines and validates the supported IV lengths.
pub trait IvParams {
    /// Returns the initialization-vector bytes.
    fn iv(&self) -> &[u8];
}

#[cfg(test)]
mod tests {
    use super::IvParams;

    struct Params<'a> {
        iv: &'a [u8],
    }

    impl IvParams for Params<'_> {
        fn iv(&self) -> &[u8] {
            self.iv
        }
    }

    #[test]
    fn value_is_reachable_through_a_trait_object() {
        let iv = [0x01_u8, 0x02, 0x03, 0x04];
        let params = Params { iv: &iv };
        let params: &dyn IvParams = &params;

        assert_eq!(params.iv(), &iv);
    }
}
