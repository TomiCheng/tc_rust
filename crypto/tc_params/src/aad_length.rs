//! Associated-data length parameter.

/// Exposes the total associated-data length required by an AEAD algorithm.
///
/// This is separate from [`InitialAadParams`](crate::InitialAadParams): the
/// initial AAD may contain only the first part of data that will later be
/// completed through the cipher's incremental AAD API.
pub trait AadLengthParams {
    /// Returns the declared total AAD length in bytes.
    fn aad_len(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::AadLengthParams;

    struct Params(usize);

    impl AadLengthParams for Params {
        fn aad_len(&self) -> usize {
            self.0
        }
    }

    #[test]
    fn value_is_reachable_through_a_trait_object() {
        let params = Params(37);
        let params: &dyn AadLengthParams = &params;
        assert_eq!(params.aad_len(), 37);
    }
}
