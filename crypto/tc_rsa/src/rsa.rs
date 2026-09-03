//! Raw RSA conversion and integer-processing contract.

use tc_bigint::BigInteger;
use tc_cipher::CipherDirection;

/// The integer-level core used by a byte-oriented RSA cipher.
///
/// `IRsa` separates RSA's byte/integer conversions from its raw modular
/// operation. A higher-level [`AsymmetricBlockCipher`](tc_cipher::AsymmetricBlockCipher)
/// can compose these steps to process one byte block.
///
/// The parameter type `P` belongs to the trait rather than to [`init`](Self::init),
/// so an initialized core can be used through `dyn IRsa<P, ...>`.
pub trait IRsa<P: ?Sized> {
    /// The failure type returned by initialization.
    type InitError: core::error::Error;

    /// The failure type returned by conversion or RSA processing.
    type Error: core::error::Error;

    /// Initializes the RSA core for encryption or decryption.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::InitError>;

    /// Returns the maximum input length in bytes for the current direction.
    fn input_block_size(&self) -> usize;

    /// Returns the maximum output length in bytes for the current direction.
    fn output_block_size(&self) -> usize;

    /// Converts a big-endian unsigned byte block into an RSA integer.
    fn convert_input(&self, input: &[u8]) -> Result<BigInteger, Self::Error>;

    /// Applies the raw RSA operation to `input`.
    fn process_block(&mut self, input: BigInteger) -> Result<BigInteger, Self::Error>;

    /// Converts an RSA integer to bytes and returns the number of bytes written.
    fn convert_output(&self, result: &BigInteger, output: &mut [u8]) -> Result<usize, Self::Error>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::convert::Infallible;
    use core::fmt;
    use std::boxed::Box;

    use super::IRsa;
    use tc_bigint::BigInteger;
    use tc_cipher::CipherDirection;

    struct TestParams;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestError;

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("output buffer is too short")
        }
    }

    impl core::error::Error for TestError {}

    struct TestRsa {
        direction: CipherDirection,
    }

    impl IRsa<TestParams> for TestRsa {
        type InitError = Infallible;
        type Error = TestError;

        fn init(
            &mut self,
            direction: CipherDirection,
            _params: &TestParams,
        ) -> Result<(), Self::InitError> {
            self.direction = direction;
            Ok(())
        }

        fn input_block_size(&self) -> usize {
            4
        }

        fn output_block_size(&self) -> usize {
            4
        }

        fn convert_input(&self, input: &[u8]) -> Result<BigInteger, Self::Error> {
            Ok(BigInteger::from_bytes_be_unsigned(input))
        }

        fn process_block(&mut self, input: BigInteger) -> Result<BigInteger, Self::Error> {
            let _ = self.direction;
            Ok(input)
        }

        fn convert_output(
            &self,
            result: &BigInteger,
            output: &mut [u8],
        ) -> Result<usize, Self::Error> {
            result
                .try_to_bytes_be_unsigned_into(output)
                .map_err(|_| TestError)
        }
    }

    #[test]
    fn supports_dynamic_dispatch() {
        let mut rsa: Box<dyn IRsa<TestParams, InitError = Infallible, Error = TestError>> =
            Box::new(TestRsa {
                direction: CipherDirection::Encrypt,
            });

        rsa.init(CipherDirection::Encrypt, &TestParams).unwrap();
        let input = rsa.convert_input(&[0x01, 0x02]).unwrap();
        let result = rsa.process_block(input).unwrap();
        let mut output = [0_u8; 4];
        let written = rsa.convert_output(&result, &mut output).unwrap();

        assert_eq!(&output[..written], &[0x01, 0x02]);
    }
}
