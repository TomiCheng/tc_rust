//! Asymmetric block-cipher contracts.

use crate::CipherDirection;

/// An initialized public-key block cipher.
///
/// Unlike a symmetric [`BlockCipher`](crate::BlockCipher), an asymmetric
/// cipher accepts a variable-length input up to [`input_block_size`](Self::input_block_size),
/// and its input and output limits may differ according to the current
/// direction and encoding layer.
///
/// This trait uses a caller-provided output buffer, so the contract itself
/// requires neither `alloc` nor `std`. Initialization is provided independently
/// by [`AsymmetricBlockCipherInit`].
///
/// Implementations with the same [`Error`](AsymmetricBlockCipher::Error) type
/// can be stored behind `dyn AsymmetricBlockCipher<Error = E>` after
/// initialization.
pub trait AsymmetricBlockCipher {
    /// The failure type returned while processing an asymmetric block.
    type Error: core::error::Error;

    /// Returns the maximum input length in bytes for the current direction.
    fn input_block_size(&self) -> usize;

    /// Returns the maximum output length in bytes for the current direction.
    fn output_block_size(&self) -> usize;

    /// Processes one variable-length asymmetric block and returns the number
    /// of bytes written to `output`.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Initializes an asymmetric block cipher from parameters of type `P`.
///
/// This trait is independent from [`AsymmetricBlockCipher`]. Consumers that
/// need both capabilities use
/// `C: AsymmetricBlockCipher + AsymmetricBlockCipherInit<P>`. Keeping `P` as a
/// trait parameter allows concrete or caller-defined public/private-key
/// parameter types to pass through composing encoding layers.
pub trait AsymmetricBlockCipherInit<P: ?Sized> {
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

    use super::{AsymmetricBlockCipher, AsymmetricBlockCipherInit};
    use crate::CipherDirection;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestError {
        NotInitialised,
        InputTooLong,
        OutputTooShort,
        InvalidCiphertext,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(match self {
                Self::NotInitialised => "asymmetric cipher not initialised",
                Self::InputTooLong => "asymmetric input is too long",
                Self::OutputTooShort => "asymmetric output buffer is too short",
                Self::InvalidCiphertext => "invalid asymmetric ciphertext",
            })
        }
    }

    impl core::error::Error for TestError {}

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestInitError;

    impl fmt::Display for TestInitError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("key must not be empty")
        }
    }

    impl core::error::Error for TestInitError {}

    struct TestParams<'a> {
        key: &'a [u8],
    }

    #[derive(Default)]
    struct TestCipher {
        direction: Option<CipherDirection>,
        mask: u8,
    }

    impl AsymmetricBlockCipher for TestCipher {
        type Error = TestError;

        fn input_block_size(&self) -> usize {
            match self.direction {
                Some(CipherDirection::Encrypt) => 3,
                Some(CipherDirection::Decrypt) => 4,
                None => 0,
            }
        }

        fn output_block_size(&self) -> usize {
            match self.direction {
                Some(CipherDirection::Encrypt) => 4,
                Some(CipherDirection::Decrypt) => 3,
                None => 0,
            }
        }

        fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            let direction = self.direction.ok_or(TestError::NotInitialised)?;
            if input.len() > self.input_block_size() {
                return Err(TestError::InputTooLong);
            }

            match direction {
                CipherDirection::Encrypt => {
                    let required = input.len() + 1;
                    if output.len() < required {
                        return Err(TestError::OutputTooShort);
                    }
                    output[0] = self.mask;
                    for (input, output) in input.iter().zip(&mut output[1..required]) {
                        *output = *input ^ self.mask;
                    }
                    Ok(required)
                }
                CipherDirection::Decrypt => {
                    let (&prefix, body) =
                        input.split_first().ok_or(TestError::InvalidCiphertext)?;
                    if prefix != self.mask {
                        return Err(TestError::InvalidCiphertext);
                    }
                    if output.len() < body.len() {
                        return Err(TestError::OutputTooShort);
                    }
                    for (input, output) in body.iter().zip(output.iter_mut()) {
                        *output = *input ^ self.mask;
                    }
                    Ok(body.len())
                }
            }
        }
    }

    impl AsymmetricBlockCipherInit<TestParams<'_>> for TestCipher {
        type Error = TestInitError;

        fn init(
            &mut self,
            direction: CipherDirection,
            params: &TestParams<'_>,
        ) -> Result<(), Self::Error> {
            self.mask = params.key.first().copied().ok_or(TestInitError)?;
            self.direction = Some(direction);
            Ok(())
        }
    }

    #[test]
    fn initialization_and_processing_support_dynamic_dispatch() {
        let params = TestParams { key: &[0x5a] };
        let plaintext = [0x11, 0x22, 0x33];

        let mut concrete = TestCipher::default();
        let initializer: &mut dyn AsymmetricBlockCipherInit<TestParams<'_>, Error = TestInitError> =
            &mut concrete;
        initializer.init(CipherDirection::Encrypt, &params).unwrap();

        let mut encryptor: Box<dyn AsymmetricBlockCipher<Error = TestError>> = Box::new(concrete);
        let mut ciphertext = [0_u8; 4];
        assert_eq!(encryptor.input_block_size(), 3);
        assert_eq!(encryptor.output_block_size(), 4);
        assert_eq!(encryptor.process_block(&plaintext, &mut ciphertext), Ok(4));

        let mut concrete = TestCipher::default();
        concrete.init(CipherDirection::Decrypt, &params).unwrap();
        let mut decryptor: Box<dyn AsymmetricBlockCipher<Error = TestError>> = Box::new(concrete);
        let mut recovered = [0_u8; 3];
        assert_eq!(decryptor.input_block_size(), 4);
        assert_eq!(decryptor.output_block_size(), 3);
        assert_eq!(decryptor.process_block(&ciphertext, &mut recovered), Ok(3));
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn initialization_has_an_independent_error_type() {
        let mut cipher = TestCipher::default();
        assert_eq!(
            cipher.init(CipherDirection::Encrypt, &TestParams { key: &[] }),
            Err(TestInitError)
        );
    }

    #[test]
    fn rejects_invalid_lengths_and_ciphertext() {
        let params = TestParams { key: &[0x5a] };
        let mut cipher = TestCipher::default();

        assert_eq!(
            cipher.process_block(&[], &mut []),
            Err(TestError::NotInitialised)
        );

        cipher.init(CipherDirection::Encrypt, &params).unwrap();
        assert_eq!(
            cipher.process_block(&[0; 4], &mut [0; 5]),
            Err(TestError::InputTooLong)
        );
        assert_eq!(
            cipher.process_block(&[0; 3], &mut [0; 3]),
            Err(TestError::OutputTooShort)
        );

        cipher.init(CipherDirection::Decrypt, &params).unwrap();
        assert_eq!(
            cipher.process_block(&[0; 4], &mut [0; 3]),
            Err(TestError::InvalidCiphertext)
        );
    }
}
