//! Authenticated-encryption cipher contracts.

use crate::CipherDirection;

/// An initialized authenticated-encryption cipher.
///
/// Initialization is provided separately by [`AeadCipherInit`], keeping this
/// operational trait available for `dyn` dispatch.
pub trait AeadCipher {
    /// The failure type returned by this cipher family.
    type Error: core::error::Error;

    /// Returns the algorithm name.
    fn algorithm_name(&self) -> &str;

    /// Adds associated data that will be authenticated but not encrypted.
    fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    /// Processes message bytes into `output` and returns the number written.
    ///
    /// During decryption, implementations may emit unauthenticated plaintext
    /// before [`do_final`](AeadCipher::do_final) verifies the authentication
    /// tag. Callers must not release that plaintext before finalization
    /// succeeds.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Finishes the operation, generating or verifying the authentication tag.
    ///
    /// Returns the number of remaining message and tag bytes written.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Returns the authentication tag from the last successfully finalized
    /// operation.
    ///
    /// Returns `None` before successful finalization, after a failed
    /// finalization, or after the cipher has been initialized or reset for a
    /// new operation.
    fn mac(&self) -> Option<&[u8]>;

    /// Returns the output capacity required by one `process_bytes` call for
    /// `input_len` additional bytes in the current state.
    fn get_update_output_size(&self, input_len: usize) -> usize;

    /// Returns the output capacity required to process `input_len` additional
    /// bytes and then finalize in the current state.
    fn get_output_size(&self, input_len: usize) -> usize;
}

/// Strongly typed initialization for an [`AeadCipher`].
///
/// [`Params`](AeadCipherInit::Params) is a generic associated type so concrete
/// engines can accept parameter objects that borrow key, nonce, or associated
/// data. It may also be an unsized trait object when an engine supports more
/// than one parameter-storage strategy.
pub trait AeadCipherInit: AeadCipher {
    /// The parameter type accepted by [`init`](AeadCipherInit::init).
    type Params<'a>: ?Sized;

    /// Initializes the cipher for encryption or decryption.
    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use core::fmt;

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

    #[derive(Debug, PartialEq, Eq)]
    enum TestError {
        OutputTooShort,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::OutputTooShort => f.write_str("output buffer is too short"),
            }
        }
    }

    impl core::error::Error for TestError {}

    #[derive(Default)]
    struct TestAeadCipher {
        direction: Option<CipherDirection>,
        key_byte: u8,
        aad_len: usize,
        mac: Option<[u8; 1]>,
    }

    impl AeadCipher for TestAeadCipher {
        type Error = TestError;

        fn algorithm_name(&self) -> &str {
            "TestAEAD"
        }

        fn process_aad_bytes(&mut self, input: &[u8]) -> Result<(), Self::Error> {
            self.mac = None;
            self.aad_len = self.aad_len.saturating_add(input.len());
            Ok(())
        }

        fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
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
            self.mac = None;
            let tag = output.first_mut().ok_or(TestError::OutputTooShort)?;
            *tag = self.key_byte ^ self.aad_len as u8;
            self.mac = Some([*tag]);
            Ok(1)
        }

        fn mac(&self) -> Option<&[u8]> {
            self.mac.as_ref().map(|mac| mac.as_slice())
        }

        fn get_update_output_size(&self, input_len: usize) -> usize {
            input_len
        }

        fn get_output_size(&self, input_len: usize) -> usize {
            input_len.saturating_add(1)
        }
    }

    impl AeadCipherInit for TestAeadCipher {
        type Params<'a> = dyn TestParams + 'a;

        fn init(
            &mut self,
            direction: CipherDirection,
            params: &Self::Params<'_>,
        ) -> Result<(), Self::Error> {
            self.direction = Some(direction);
            self.key_byte = params.key_byte();
            self.mac = None;
            Ok(())
        }
    }

    #[test]
    fn initialized_cipher_supports_dynamic_dispatch() {
        let owned = OwnedParams { key: 0xA5 };
        let mut concrete = TestAeadCipher::default();
        concrete.init(CipherDirection::Encrypt, &owned).unwrap();
        let cipher: &mut dyn AeadCipher<Error = TestError> = &mut concrete;

        assert_eq!(cipher.algorithm_name(), "TestAEAD");
        assert_eq!(cipher.get_update_output_size(3), 3);
        assert_eq!(cipher.get_output_size(3), 4);
        assert_eq!(cipher.mac(), None);

        cipher.process_aad_bytes(&[0x10, 0x20]).unwrap();
        let mut output = [0_u8; 3];
        assert_eq!(
            cipher.process_bytes(&[0x00, 0xA5, 0xFF], &mut output),
            Ok(3)
        );
        assert_eq!(output, [0xA5, 0x00, 0x5A]);

        let mut final_output = [0_u8; 1];
        assert_eq!(cipher.do_final(&mut final_output), Ok(1));
        assert_eq!(final_output, [0xA7]);
        assert_eq!(cipher.mac(), Some(&[0xA7][..]));

        cipher.process_aad_bytes(&[0x30]).unwrap();
        assert_eq!(cipher.mac(), None);

        assert_eq!(
            cipher.process_bytes(&[0_u8; 2], &mut [0_u8; 1]),
            Err(TestError::OutputTooShort)
        );
    }

    #[test]
    fn init_accepts_borrowed_and_owned_parameter_implementations() {
        let key = 0xA5;
        let borrowed = BorrowedParams { key: &key };
        let mut cipher = TestAeadCipher::default();

        cipher.init(CipherDirection::Encrypt, &borrowed).unwrap();
        assert_eq!(cipher.direction, Some(CipherDirection::Encrypt));
        assert_eq!(cipher.key_byte, 0xA5);

        let owned = OwnedParams { key: 0x5A };
        cipher.init(CipherDirection::Decrypt, &owned).unwrap();
        assert_eq!(cipher.direction, Some(CipherDirection::Decrypt));
        assert_eq!(cipher.key_byte, 0x5A);
    }
}
