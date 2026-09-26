//! Initialization-vector parameter abstraction.

/// Parameters that provide an initialization vector.
///
/// Implementations only expose the caller's value. The consuming mode
/// defines and validates the supported IV lengths. Implement this trait,
/// alongside the engine's parameter trait, to pass your own parameter type to
/// a mode, or use [`KeyWithIvRef`](crate::KeyWithIvRef),
/// [`KeyWithIvFixed`](crate::KeyWithIvFixed) or `KeyWithIvOwned`.
pub trait IvParams {
    /// Returns the initialization-vector bytes.
    ///
    /// Constant time in this crate's containers, which return their slice
    /// without inspecting it; other implementations define their own timing.
    fn iv(&self) -> &[u8];
}

/// Parameters that may provide an initialization vector.
///
/// CBC (runtime-sized), CFB and OFB accept this trait and treat an omitted IV
/// as all zeros. Every [`IvParams`] type implements it and returns `Some`.
///
/// # Example
///
/// A key-only parameter type for a mode that allows omitting the IV:
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyParams};
/// use tc_block_modes::{FixedCfbBlockCipher, IvOptParams, KeyWithIvRef};
///
/// struct KeyOnly<'a>(&'a [u8]);
///
/// impl KeyParams for KeyOnly<'_> {
///     fn key(&self) -> &[u8] {
///         self.0
///     }
/// }
///
/// impl IvOptParams for KeyOnly<'_> {
///     fn iv_opt(&self) -> Option<&[u8]> {
///         None
///     }
/// }
///
/// let key = [0x42; 16];
/// let mut mode = FixedCfbBlockCipher::<_, 16, 16>::new(AesEngine::new());
/// let mut omitted = [0; 16];
/// mode.init(CipherDirection::Encrypt, &KeyOnly(&key))?;
/// mode.process_block(&[0; 16], &mut omitted)?;
///
/// let mut zero = [0; 16];
/// mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &[0; 16]))?;
/// mode.process_block(&[0; 16], &mut zero)?;
/// assert_eq!(omitted, zero);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub trait IvOptParams {
    /// Returns the initialization-vector bytes when supplied.
    ///
    /// Constant time in this crate's implementations, which return a slice
    /// without inspecting it; other implementations define their own timing.
    fn iv_opt(&self) -> Option<&[u8]>;
}

impl<T: IvParams + ?Sized> IvOptParams for T {
    /// Returns `Some` with the required IV. Constant time when `iv` is.
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
