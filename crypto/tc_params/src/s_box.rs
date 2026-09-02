//! Substitution-box parameter abstraction.

/// Parameters that provide substitution-box bytes.
///
/// Implementations only expose the caller's value. The consuming algorithm
/// defines and validates the supported tables and lengths.
pub trait SBoxParams {
    /// Returns the substitution-box bytes.
    fn s_box(&self) -> &[u8];
}

#[cfg(test)]
mod tests {
    use super::SBoxParams;

    struct Params<'a> {
        s_box: &'a [u8],
    }

    impl SBoxParams for Params<'_> {
        fn s_box(&self) -> &[u8] {
            self.s_box
        }
    }

    #[test]
    fn value_is_reachable_through_a_trait_object() {
        let table = [0x0a_u8, 0x0b];
        let params = Params { s_box: &table };
        let params: &dyn SBoxParams = &params;

        assert_eq!(params.s_box(), &table);
    }
}
