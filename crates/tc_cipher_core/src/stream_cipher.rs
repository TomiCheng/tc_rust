//! Stream-cipher contracts.

/// An initialized symmetric-key stream cipher.
///
/// This trait contains only operations that can be dispatched through a trait
/// object. Initialization is provided separately by [`StreamCipherInit`], whose
/// generic associated parameter type is intentionally kept out of this trait.
///
/// Implementations with the same [`Error`](StreamCipher::Error) type can be
/// stored behind `dyn StreamCipher<Error = E>` after they have been initialized.
pub trait StreamCipher {
    /// The failure type returned by stream-processing operations.
    type Error: core::error::Error;

    /// Returns the algorithm name.
    fn algorithm_name(&self) -> &str;

    /// Encrypts or decrypts one byte and advances the keystream.
    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error>;

    /// Processes `input` into `output` and returns the number of bytes written.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Restores the state established by the most recent initialization.
    fn reset(&mut self);
}

/// Strongly typed initialization for a [`StreamCipher`].
///
/// The generic associated type permits parameter objects that borrow key or
/// nonce material. Because that GAT is not part of [`StreamCipher`], initialized
/// implementations can still be used through `dyn StreamCipher`.
pub trait StreamCipherInit: StreamCipher {
    /// The parameter type accepted by [`init`](StreamCipherInit::init).
    type Params<'a>;

    /// Initializes the cipher with the supplied parameters.
    ///
    /// Most stream ciphers use the same operation for encryption and
    /// decryption, but `for_encryption` is retained for algorithms that need to
    /// distinguish the direction.
    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::convert::Infallible;
    use std::boxed::Box;

    use super::{StreamCipher, StreamCipherInit};

    #[derive(Default)]
    struct TestCipher {
        key_byte: u8,
    }

    struct TestParams<'a> {
        key: &'a [u8],
    }

    impl StreamCipher for TestCipher {
        type Error = Infallible;

        fn algorithm_name(&self) -> &str {
            "Test"
        }

        fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
            Ok(input ^ self.key_byte)
        }

        fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            for (input, output) in input.iter().zip(output.iter_mut()) {
                *output = *input ^ self.key_byte;
            }

            Ok(input.len())
        }

        fn reset(&mut self) {}
    }

    impl StreamCipherInit for TestCipher {
        type Params<'a> = TestParams<'a>;

        fn init(
            &mut self,
            _for_encryption: bool,
            params: &Self::Params<'_>,
        ) -> Result<(), Self::Error> {
            self.key_byte = params.key[0];
            Ok(())
        }
    }

    #[test]
    fn initialized_cipher_supports_dynamic_dispatch() {
        let mut concrete = TestCipher::default();
        let params = TestParams { key: &[0xa5] };
        concrete.init(true, &params).unwrap();

        let mut cipher: Box<dyn StreamCipher<Error = Infallible>> = Box::new(concrete);
        let mut output = [0_u8; 3];

        assert_eq!(cipher.algorithm_name(), "Test");
        assert_eq!(
            cipher.process_bytes(&[0x00, 0xa5, 0xff], &mut output),
            Ok(3)
        );
        assert_eq!(output, [0xa5, 0x00, 0x5a]);
        assert_eq!(cipher.return_byte(0x5a), Ok(0xff));
        cipher.reset();
    }
}
