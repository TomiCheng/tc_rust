//! Initialization-vector parameter abstraction.

/// Parameters that provide an initialization vector.
///
/// Implementations only expose the caller's value. The consuming mode or
/// algorithm defines and validates the supported IV lengths.
pub trait IvParams {
    /// Returns the initialization-vector bytes.
    fn iv(&self) -> &[u8];
}

/// Parameters that may provide an initialization vector.
///
/// Modes that define behavior for an omitted IV can accept this trait instead
/// of [`IvParams`]. Types with a required IV automatically implement this
/// trait and return `Some`.
pub trait IvOptParams {
    /// Returns the initialization-vector bytes when supplied.
    fn iv_opt(&self) -> Option<&[u8]>;
}

impl<T: IvParams + ?Sized> IvOptParams for T {
    fn iv_opt(&self) -> Option<&[u8]> {
        Some(self.iv())
    }
}

#[cfg(test)]
mod tests {
    use super::{IvParams, IvOptParams};

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

    #[test]
    fn required_iv_is_available_through_the_optional_contract() {
        let iv = [0x01_u8, 0x02, 0x03, 0x04];
        let params = Params { iv: &iv };
        let params: &dyn IvOptParams = &params;

        assert_eq!(params.iv_opt(), Some(iv.as_slice()));
    }

    #[test]
    fn optional_contract_can_represent_an_omitted_iv() {
        struct NoIv;

        impl IvOptParams for NoIv {
            fn iv_opt(&self) -> Option<&[u8]> {
                None
            }
        }

        let params: &dyn IvOptParams = &NoIv;
        assert_eq!(params.iv_opt(), None);
    }
}
