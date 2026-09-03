//! Integrated Encryption Scheme (IES) contracts.

use crate::CipherDirection;

/// A one-shot Integrated Encryption Scheme engine.
///
/// IES authenticates the complete message, so adapters collect all input and
/// call [`process_block`](Self::process_block) only during finalization.
pub trait IesCipher {
    /// The failure type returned while processing a complete message.
    type Error: core::error::Error;

    /// Returns the output capacity required for a message of `input_len` bytes
    /// under the current initialization parameters and direction.
    fn get_output_size(&self, input_len: usize) -> usize;

    /// Processes one complete message and returns the number of bytes written.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Initializes an IES engine from parameters of type `P`.
///
/// This trait is separate from [`IesCipher`] so caller-owned parameter traits
/// can be composed without fixing one concrete parameter container.
pub trait IesCipherInit<P: ?Sized> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the engine for encryption or decryption.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::boxed::Box;

    use super::{IesCipher, IesCipherInit};
    use crate::{CipherDirection, InitError, StreamError};

    struct Params;

    struct TestIes {
        direction: CipherDirection,
    }

    impl IesCipher for TestIes {
        type Error = StreamError;

        fn get_output_size(&self, input_len: usize) -> usize {
            match self.direction {
                CipherDirection::Encrypt => input_len + 1,
                CipherDirection::Decrypt => input_len.saturating_sub(1),
            }
        }

        fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            let required = self.get_output_size(input.len());
            if output.len() < required {
                return Err(StreamError::BufferTooShort);
            }
            match self.direction {
                CipherDirection::Encrypt => {
                    output[..input.len()].copy_from_slice(input);
                    output[input.len()] = 0;
                }
                CipherDirection::Decrypt => {
                    output[..required].copy_from_slice(&input[..required]);
                }
            }
            Ok(required)
        }
    }

    impl IesCipherInit<Params> for TestIes {
        type Error = InitError;

        fn init(
            &mut self,
            direction: CipherDirection,
            _params: &Params,
        ) -> Result<(), Self::Error> {
            self.direction = direction;
            Ok(())
        }
    }

    #[test]
    fn processing_and_initialization_support_dynamic_dispatch() {
        let mut concrete = TestIes {
            direction: CipherDirection::Encrypt,
        };
        let init: &mut dyn IesCipherInit<Params, Error = InitError> = &mut concrete;
        init.init(CipherDirection::Decrypt, &Params).unwrap();

        let mut cipher: Box<dyn IesCipher<Error = StreamError>> = Box::new(concrete);
        let mut output = [0u8; 2];
        assert_eq!(cipher.get_output_size(3), 2);
        assert_eq!(cipher.process_block(&[1, 2, 3], &mut output), Ok(2));
        assert_eq!(output, [1, 2]);
    }
}
