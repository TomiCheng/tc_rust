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
pub trait OptionalIvParams {
    /// Returns the initialization-vector bytes when supplied.
    fn optional_iv(&self) -> Option<&[u8]>;
}

impl<T: IvParams + ?Sized> OptionalIvParams for T {
    fn optional_iv(&self) -> Option<&[u8]> {
        Some(self.iv())
    }
}

#[cfg(test)]
mod tests {
    use super::{IvParams, OptionalIvParams};

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
        let params: &dyn OptionalIvParams = &params;

        assert_eq!(params.optional_iv(), Some(iv.as_slice()));
    }

    #[test]
    fn optional_contract_can_represent_an_omitted_iv() {
        struct NoIv;

        impl OptionalIvParams for NoIv {
            fn optional_iv(&self) -> Option<&[u8]> {
                None
            }
        }

        let params: &dyn OptionalIvParams = &NoIv;
        assert_eq!(params.optional_iv(), None);
    }
}
