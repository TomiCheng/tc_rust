//! Authentication-tag size parameters.

/// Provides the requested authentication-tag size in bytes.
///
/// Each algorithm validates the sizes it supports during initialization.
pub trait MacSizeParams {
    /// Returns the authentication-tag size in bytes.
    fn mac_size(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::MacSizeParams;

    struct Params(usize);

    impl MacSizeParams for Params {
        fn mac_size(&self) -> usize {
            self.0
        }
    }

    #[test]
    fn supports_dynamic_dispatch() {
        let params: &dyn MacSizeParams = &Params(12);
        assert_eq!(params.mac_size(), 12);
    }
}
