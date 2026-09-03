//! Raw RSA conversion and integer-processing contract.

use tc_cipher::CipherDirection;

use crate::{BigInt, RsaKeyParams};

/// The integer-level core used by a byte-oriented RSA cipher.
///
/// `RsaCore` separates RSA's byte/integer conversions from its raw modular
/// operation. A higher-level [`AsymmetricBlockCipher`](tc_cipher::AsymmetricBlockCipher)
/// can compose these steps to process one byte block.
///
/// The key-parameter type `K` belongs to the trait rather than to
/// [`init`](Self::init), so an initialized core can be used through
/// `dyn RsaCore<K, I, ...>`.
pub trait RsaCore<K: ?Sized, I>
where
    K: RsaKeyParams<I>,
    I: BigInt,
{
    /// The failure type returned by initialization.
    type InitError: core::error::Error;

    /// The failure type returned by conversion or RSA processing.
    type Error: core::error::Error;

    /// Initializes the RSA core for encryption or decryption.
    fn init(&mut self, direction: CipherDirection, params: &K) -> Result<(), Self::InitError>;

    /// Returns the maximum input length in bytes for the current direction.
    fn input_block_size(&self) -> usize;

    /// Returns the maximum output length in bytes for the current direction.
    fn output_block_size(&self) -> usize;

    /// Converts a big-endian unsigned byte block into an RSA integer.
    fn convert_input(&self, input: &[u8]) -> Result<I, Self::Error>;

    /// Applies the raw RSA operation to `input`.
    fn process_block(&mut self, input: I) -> Result<I, Self::Error>;

    /// Converts an RSA integer to bytes and returns the number of bytes written.
    fn convert_output(&self, result: &I, output: &mut [u8]) -> Result<usize, Self::Error>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::convert::Infallible;
    use core::fmt;
    use std::boxed::Box;

    use super::RsaCore;
    use crate::{BigInt, RsaKeyParams};
    use tc_cipher::CipherDirection;

    struct TestBigInt(u32);

    impl BigInt for TestBigInt {}

    struct TestParams {
        modulus: TestBigInt,
        exponent: TestBigInt,
    }

    impl RsaKeyParams<TestBigInt> for TestParams {
        fn modulus(&self) -> &TestBigInt {
            &self.modulus
        }

        fn exponent(&self) -> &TestBigInt {
            &self.exponent
        }
    }

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

    impl RsaCore<TestParams, TestBigInt> for TestRsa {
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

        fn convert_input(&self, input: &[u8]) -> Result<TestBigInt, Self::Error> {
            let value = input
                .iter()
                .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte));
            Ok(TestBigInt(value))
        }

        fn process_block(&mut self, input: TestBigInt) -> Result<TestBigInt, Self::Error> {
            let _ = self.direction;
            Ok(input)
        }

        fn convert_output(
            &self,
            result: &TestBigInt,
            output: &mut [u8],
        ) -> Result<usize, Self::Error> {
            let bytes = result.0.to_be_bytes();
            let start = bytes
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(bytes.len() - 1);
            let bytes = &bytes[start..];
            if output.len() < bytes.len() {
                return Err(TestError);
            }
            output[..bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        }
    }

    #[test]
    fn supports_dynamic_dispatch() {
        let mut rsa: Box<
            dyn RsaCore<TestParams, TestBigInt, InitError = Infallible, Error = TestError>,
        > = Box::new(TestRsa {
            direction: CipherDirection::Encrypt,
        });

        let params = TestParams {
            modulus: TestBigInt(3233),
            exponent: TestBigInt(17),
        };
        rsa.init(CipherDirection::Encrypt, &params).unwrap();
        let input = rsa.convert_input(&[0x01, 0x02]).unwrap();
        let result = rsa.process_block(input).unwrap();
        let mut output = [0_u8; 4];
        let written = rsa.convert_output(&result, &mut output).unwrap();

        assert_eq!(&output[..written], &[0x01, 0x02]);
    }
}
