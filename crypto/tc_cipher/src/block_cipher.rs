//! Block-cipher contracts.

use crate::CipherDirection;

/// An initialized symmetric-key block cipher.
///
/// This trait contains only operations that can be dispatched through a trait
/// object. Initialization is provided separately by [`BlockCipherInit`], whose
/// generic associated parameter type is intentionally kept out of this trait.
///
/// Implementations with the same [`Error`](BlockCipher::Error) type can be
/// stored behind `dyn BlockCipher<Error = E>` after they have been initialized.
pub trait BlockCipher {
    /// The failure type returned by block-processing operations.
    type Error: core::error::Error;

    /// Returns the block size in bytes.
    fn block_size(&self) -> usize;

    /// Processes one block and returns the number of bytes written.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Strongly typed initialization for a [`BlockCipher`].
///
/// The generic associated type permits parameter objects that borrow key or
/// tweak material. Because that GAT is not part of [`BlockCipher`], initialized
/// implementations can still be used through `dyn BlockCipher`.
pub trait BlockCipherInit: BlockCipher {
    /// The parameter type accepted by [`init`](BlockCipherInit::init).
    type Params<'a>;

    /// Initializes the cipher for the selected transformation direction.
    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::fmt;
    use std::boxed::Box;

    use super::{BlockCipher, BlockCipherInit};
    use crate::CipherDirection;

    const BLOCK_SIZE: usize = 4;

    #[derive(Debug, PartialEq, Eq)]
    enum TestError {
        BufferTooShort,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::BufferTooShort => f.write_str("buffer is shorter than one block"),
            }
        }
    }

    impl core::error::Error for TestError {}

    struct TestParams<'a> {
        key: &'a [u8],
    }

    struct TestCipher {
        direction: CipherDirection,
        key_byte: u8,
    }

    impl TestCipher {
        const fn new() -> Self {
            Self {
                direction: CipherDirection::Encrypt,
                key_byte: 0,
            }
        }
    }

    impl BlockCipher for TestCipher {
        type Error = TestError;

        fn block_size(&self) -> usize {
            BLOCK_SIZE
        }

        fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            if input.len() < BLOCK_SIZE || output.len() < BLOCK_SIZE {
                return Err(TestError::BufferTooShort);
            }

            for (input, output) in input[..BLOCK_SIZE].iter().zip(&mut output[..BLOCK_SIZE]) {
                *output = match self.direction {
                    CipherDirection::Encrypt => input.wrapping_add(self.key_byte),
                    CipherDirection::Decrypt => input.wrapping_sub(self.key_byte),
                };
            }

            Ok(BLOCK_SIZE)
        }
    }

    impl BlockCipherInit for TestCipher {
        type Params<'a> = TestParams<'a>;

        fn init(
            &mut self,
            direction: CipherDirection,
            params: &Self::Params<'_>,
        ) -> Result<(), Self::Error> {
            self.direction = direction;
            self.key_byte = params.key[0];
            Ok(())
        }
    }

    #[test]
    fn initialized_ciphers_support_dynamic_dispatch_in_both_directions() {
        let params = TestParams { key: &[0x10] };
        let plaintext = [0x00, 0x7f, 0xf0, 0xff];

        let mut encryptor = TestCipher::new();
        encryptor.init(CipherDirection::Encrypt, &params).unwrap();
        let mut encryptor: Box<dyn BlockCipher<Error = TestError>> = Box::new(encryptor);
        let mut ciphertext = [0_u8; BLOCK_SIZE];

        assert_eq!(encryptor.block_size(), BLOCK_SIZE);
        assert_eq!(
            encryptor.process_block(&plaintext, &mut ciphertext),
            Ok(BLOCK_SIZE)
        );

        let mut decryptor = TestCipher::new();
        decryptor.init(CipherDirection::Decrypt, &params).unwrap();
        let mut decryptor: Box<dyn BlockCipher<Error = TestError>> = Box::new(decryptor);
        let mut recovered = [0_u8; BLOCK_SIZE];

        assert_eq!(
            decryptor.process_block(&ciphertext, &mut recovered),
            Ok(BLOCK_SIZE)
        );
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn rejects_short_buffers() {
        let mut cipher = TestCipher::new();
        cipher
            .init(CipherDirection::Encrypt, &TestParams { key: &[0x10] })
            .unwrap();

        assert_eq!(
            cipher.process_block(&[0_u8; BLOCK_SIZE - 1], &mut [0_u8; BLOCK_SIZE]),
            Err(TestError::BufferTooShort)
        );
        assert_eq!(
            cipher.process_block(&[0_u8; BLOCK_SIZE], &mut [0_u8; BLOCK_SIZE - 1]),
            Err(TestError::BufferTooShort)
        );
    }
}
