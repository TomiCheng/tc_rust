//! Stream-cipher contracts.

use crate::CipherDirection;

/// An initialized symmetric-key stream cipher.
///
/// This trait contains only operations that can be dispatched through a trait
/// object. Initialization is provided independently by [`StreamCipherInit`].
///
/// Implementations with the same [`Error`](StreamCipher::Error) type can be
/// stored together behind `dyn StreamCipher<Error = E>` after initialization.
pub trait StreamCipher {
    /// The failure type returned by initialization and stream processing.
    type Error: core::error::Error;

    /// Encrypts or decrypts one byte and advances the keystream.
    fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error>;

    /// Processes `input` into `output` and returns the number of bytes written.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Restores the state established by the most recent initialization.
    fn reset(&mut self);
}

/// Initializes an object from parameters of type `P`.
///
/// This trait is independent from [`StreamCipher`]. Consumers that need both
/// capabilities use `C: StreamCipher + StreamCipherInit<P>`. Keeping `P` as a
/// trait parameter lets one caller-owned parameter object flow through any
/// number of composing cipher layers.
pub trait StreamCipherInit<P: ?Sized> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the cipher with the supplied parameters.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::fmt;
    use std::boxed::Box;

    use super::{StreamCipher, StreamCipherInit};
    use crate::CipherDirection;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestError {
        NotInitialised,
        BufferTooShort,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{self:?}")
        }
    }

    impl core::error::Error for TestError {}

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestInitError(usize);

    impl fmt::Display for TestInitError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "invalid key length: {}", self.0)
        }
    }

    impl core::error::Error for TestInitError {}

    struct TestParams<'a> {
        key: &'a [u8],
    }

    struct TestCipher {
        initialised: bool,
        direction: CipherDirection,
        initial_key_byte: u8,
        key_byte: u8,
    }

    impl TestCipher {
        const fn new() -> Self {
            Self {
                initialised: false,
                direction: CipherDirection::Encrypt,
                initial_key_byte: 0,
                key_byte: 0,
            }
        }
    }

    impl StreamCipher for TestCipher {
        type Error = TestError;

        fn return_byte(&mut self, input: u8) -> Result<u8, Self::Error> {
            if !self.initialised {
                return Err(TestError::NotInitialised);
            }

            let output = input ^ self.key_byte;
            self.key_byte = self.key_byte.wrapping_add(1);
            Ok(output)
        }

        fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            if !self.initialised {
                return Err(TestError::NotInitialised);
            }
            if output.len() < input.len() {
                return Err(TestError::BufferTooShort);
            }

            for (input, output) in input.iter().zip(output.iter_mut()) {
                *output = *input ^ self.key_byte;
                self.key_byte = self.key_byte.wrapping_add(1);
            }
            Ok(input.len())
        }

        fn reset(&mut self) {
            self.key_byte = self.initial_key_byte;
        }
    }

    impl StreamCipherInit<TestParams<'_>> for TestCipher {
        type Error = TestInitError;

        fn init(
            &mut self,
            direction: CipherDirection,
            params: &TestParams<'_>,
        ) -> Result<(), Self::Error> {
            let key_byte = params.key.first().copied().ok_or(TestInitError(0))?;
            self.direction = direction;
            self.initial_key_byte = key_byte;
            self.key_byte = key_byte;
            self.initialised = true;
            Ok(())
        }
    }

    #[test]
    fn initialized_cipher_supports_dynamic_dispatch_and_reset() {
        let mut concrete = TestCipher::new();
        let initializer: &mut dyn StreamCipherInit<TestParams<'_>, Error = TestInitError> =
            &mut concrete;
        initializer
            .init(CipherDirection::Encrypt, &TestParams { key: &[0xa5] })
            .expect("valid key");
        assert_eq!(concrete.direction, CipherDirection::Encrypt);

        let mut cipher: Box<dyn StreamCipher<Error = TestError>> = Box::new(concrete);
        let mut output = [0_u8; 3];
        assert_eq!(
            cipher.process_bytes(&[0x00, 0xa5, 0xff], &mut output),
            Ok(3)
        );
        assert_eq!(output, [0xa5, 0x03, 0x58]);
        assert_eq!(cipher.return_byte(0x5a), Ok(0xf2));

        cipher.reset();
        assert_eq!(cipher.return_byte(0x5a), Ok(0xff));
    }

    #[test]
    fn reports_initialization_and_processing_errors() {
        let mut cipher = TestCipher::new();
        assert_eq!(cipher.return_byte(0), Err(TestError::NotInitialised));
        assert_eq!(
            cipher.init(CipherDirection::Encrypt, &TestParams { key: &[] }),
            Err(TestInitError(0))
        );

        cipher
            .init(CipherDirection::Decrypt, &TestParams { key: &[1] })
            .unwrap();
        assert_eq!(cipher.direction, CipherDirection::Decrypt);
        assert_eq!(
            cipher.process_bytes(&[0; 2], &mut [0; 1]),
            Err(TestError::BufferTooShort)
        );
    }
}
