//! Authenticated-encryption cipher contracts.

use crate::CipherDirection;

/// An initialized authenticated-encryption cipher.
///
/// This trait contains only operations that can be dispatched through a trait
/// object. Initialization is provided independently by [`AeadCipherInit`].
///
/// Implementations with the same [`Error`](AeadCipher::Error) type can be
/// stored together behind `dyn AeadCipher<Error = E>` after initialization.
pub trait AeadCipher {
    /// The failure type returned by AEAD processing and finalization.
    type Error: core::error::Error;

    /// Adds associated data that is authenticated but not encrypted.
    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// Processes message bytes into `output` and returns the number written.
    ///
    /// During decryption, an implementation may emit unauthenticated plaintext
    /// before [`do_final`](AeadCipher::do_final) verifies the authentication
    /// tag. Callers must not release that plaintext before finalization
    /// succeeds.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Finishes the operation, generating or verifying the authentication tag.
    ///
    /// Returns the number of remaining message or tag bytes written.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Returns the tag from the last successfully finalized operation.
    ///
    /// Returns `None` before successful finalization, after failed
    /// finalization, or after the cipher starts a new operation.
    fn mac(&self) -> Option<&[u8]>;

    /// Discards data from the current operation and restores the state
    /// established by the most recent successful initialization.
    ///
    /// Implementations may keep an encryption cipher finalized when restoring
    /// it would reuse a key and nonce. Such a cipher must be initialized with a
    /// fresh nonce before it can encrypt another message.
    fn reset(&mut self);

    /// Returns the output capacity required by one [`process_bytes`](Self::process_bytes)
    /// call for `input_len` additional bytes in the current state.
    fn get_update_output_size(&self, input_len: usize) -> usize;

    /// Returns the output capacity required to process `input_len` additional
    /// bytes and then finalize in the current state.
    fn get_output_size(&self, input_len: usize) -> usize;
}

/// Initializes an authenticated-encryption cipher from parameters of type `P`.
///
/// This trait is independent from [`AeadCipher`]. Consumers that need both
/// capabilities use `C: AeadCipher + AeadCipherInit<P>`. Keeping `P` as a trait
/// parameter lets one caller-owned parameter object flow through composing
/// cryptographic layers.
pub trait AeadCipherInit<P: ?Sized> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the cipher for encryption or decryption.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::fmt;
    use std::boxed::Box;

    use super::{AeadCipher, AeadCipherInit};
    use crate::CipherDirection;

    trait TestParams {
        fn key_byte(&self) -> u8;
    }

    struct BorrowedParams<'a> {
        key: &'a u8,
    }

    impl TestParams for BorrowedParams<'_> {
        fn key_byte(&self) -> u8 {
            *self.key
        }
    }

    struct OwnedParams {
        key: u8,
    }

    impl TestParams for OwnedParams {
        fn key_byte(&self) -> u8 {
            self.key
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestError {
        NotInitialised,
        OutputTooShort,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{self:?}")
        }
    }

    impl core::error::Error for TestError {}

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestInitError;

    impl fmt::Display for TestInitError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("key byte must not be zero")
        }
    }

    impl core::error::Error for TestInitError {}

    #[derive(Default)]
    struct TestAeadCipher {
        direction: Option<CipherDirection>,
        key_byte: u8,
        aad_len: usize,
        mac: Option<[u8; 1]>,
    }

    impl AeadCipher for TestAeadCipher {
        type Error = TestError;

        fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error> {
            if self.direction.is_none() {
                return Err(TestError::NotInitialised);
            }
            self.mac = None;
            self.aad_len = self.aad_len.saturating_add(input.len());
            Ok(())
        }

        fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            if self.direction.is_none() {
                return Err(TestError::NotInitialised);
            }
            if output.len() < input.len() {
                return Err(TestError::OutputTooShort);
            }

            self.mac = None;
            for (input, output) in input.iter().zip(output.iter_mut()) {
                *output = *input ^ self.key_byte;
            }
            Ok(input.len())
        }

        fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            if self.direction.is_none() {
                return Err(TestError::NotInitialised);
            }
            self.mac = None;
            let tag = output.first_mut().ok_or(TestError::OutputTooShort)?;
            *tag = self.key_byte ^ self.aad_len as u8;
            self.mac = Some([*tag]);
            Ok(1)
        }

        fn mac(&self) -> Option<&[u8]> {
            self.mac.as_ref().map(|mac| mac.as_slice())
        }

        fn reset(&mut self) {
            self.aad_len = 0;
            self.mac = None;
        }

        fn get_update_output_size(&self, input_len: usize) -> usize {
            input_len
        }

        fn get_output_size(&self, input_len: usize) -> usize {
            input_len.saturating_add(1)
        }
    }

    impl<P: TestParams + ?Sized> AeadCipherInit<P> for TestAeadCipher {
        type Error = TestInitError;

        fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
            let key_byte = params.key_byte();
            if key_byte == 0 {
                return Err(TestInitError);
            }
            self.direction = Some(direction);
            self.key_byte = key_byte;
            self.aad_len = 0;
            self.mac = None;
            Ok(())
        }
    }

    #[test]
    fn initialized_cipher_supports_dynamic_dispatch() {
        let params = OwnedParams { key: 0xa5 };
        let mut concrete = TestAeadCipher::default();
        let initializer: &mut dyn AeadCipherInit<OwnedParams, Error = TestInitError> =
            &mut concrete;
        initializer.init(CipherDirection::Encrypt, &params).unwrap();
        let mut cipher: Box<dyn AeadCipher<Error = TestError>> = Box::new(concrete);

        assert_eq!(cipher.get_update_output_size(3), 3);
        assert_eq!(cipher.get_output_size(3), 4);
        assert_eq!(cipher.mac(), None);
        cipher.process_aad_bytes(&[0x10, 0x20]).unwrap();

        let mut output = [0u8; 3];
        assert_eq!(
            cipher.process_bytes(&[0x00, 0xa5, 0xff], &mut output),
            Ok(3)
        );
        assert_eq!(output, [0xa5, 0x00, 0x5a]);

        let mut final_output = [0u8; 1];
        assert_eq!(cipher.do_final(&mut final_output), Ok(1));
        assert_eq!(final_output, [0xa7]);
        assert_eq!(cipher.mac(), Some(&[0xa7][..]));

        cipher.reset();
        assert_eq!(cipher.mac(), None);
        let mut reset_output = [0u8; 1];
        assert_eq!(cipher.do_final(&mut reset_output), Ok(1));
        assert_eq!(reset_output, [0xa5]);
    }

    #[test]
    fn init_accepts_borrowed_owned_and_trait_object_params() {
        let key = 0xa5;
        let borrowed = BorrowedParams { key: &key };
        let mut cipher = TestAeadCipher::default();
        cipher.init(CipherDirection::Encrypt, &borrowed).unwrap();
        assert_eq!(cipher.key_byte, 0xa5);

        let owned = OwnedParams { key: 0x5a };
        let params: &dyn TestParams = &owned;
        cipher.init(CipherDirection::Decrypt, params).unwrap();
        assert_eq!(cipher.direction, Some(CipherDirection::Decrypt));
        assert_eq!(cipher.key_byte, 0x5a);

        assert_eq!(
            cipher.init(CipherDirection::Encrypt, &OwnedParams { key: 0 }),
            Err(TestInitError)
        );
    }

    #[test]
    fn mac_is_available_only_after_successful_finalization() {
        let mut cipher = TestAeadCipher::default();
        assert_eq!(cipher.mac(), None);
        assert_eq!(
            cipher.process_aad_bytes(&[]),
            Err(TestError::NotInitialised)
        );

        cipher
            .init(CipherDirection::Encrypt, &OwnedParams { key: 1 })
            .unwrap();
        assert_eq!(cipher.do_final(&mut [0u8; 1]), Ok(1));
        assert_eq!(cipher.mac(), Some(&[1][..]));

        assert_eq!(cipher.do_final(&mut []), Err(TestError::OutputTooShort));
        assert_eq!(cipher.mac(), None);
    }
}
