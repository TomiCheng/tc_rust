//! Initialization-vector parameter abstraction.

/// Parameters that provide an initialization vector.
///
/// Implementations only expose the caller's value. The consuming mode
/// defines and validates the supported IV lengths: CBC takes exactly one
/// block, CFB and OFB take up to one block and right-align a shorter one over
/// zeros, and CTR fills the leading bytes of its counter block. Implement this
/// trait, alongside the engine's parameter trait, to pass your own parameter
/// type to a mode, or use [`KeyWithIvRef`](crate::KeyWithIvRef),
/// [`KeyWithIvFixed`](crate::KeyWithIvFixed) or `KeyWithIvOwned`.
///
/// # Example
///
/// A custom parameter type; for CFB, its empty IV acts as an all-zero IV:
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyParams};
/// use tc_block_modes::{FixedCfbBlockCipher, IvParams, KeyWithIvRef};
///
/// struct Session {
///     key: [u8; 16],
///     iv: Vec<u8>,
/// }
///
/// impl KeyParams for Session {
///     fn key(&self) -> &[u8] {
///         &self.key
///     }
/// }
///
/// impl IvParams for Session {
///     fn iv(&self) -> &[u8] {
///         &self.iv
///     }
/// }
///
/// let session = Session { key: [0x42; 16], iv: Vec::new() };
/// let mut mode = FixedCfbBlockCipher::<_, 16, 16>::new(AesEngine::new());
/// let mut empty = [0; 16];
/// mode.init(CipherDirection::Encrypt, &session)?;
/// mode.process_block(&[0; 16], &mut empty)?;
///
/// let mut zero = [0; 16];
/// mode.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&session.key, &[0; 16]))?;
/// mode.process_block(&[0; 16], &mut zero)?;
/// assert_eq!(empty, zero);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub trait IvParams {
    /// Returns the initialization-vector bytes.
    ///
    /// Constant time in this crate's containers, which return their slice
    /// without inspecting it; other implementations define their own timing.
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
