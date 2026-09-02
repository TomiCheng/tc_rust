//! Block-cipher contracts.

use crate::CipherDirection;

/// An initialized symmetric-key block cipher.
///
/// This trait contains only operations that can be dispatched through a trait
/// object. Initialization is provided independently by [`BlockCipherInit`].
///
/// Implementations with the same [`Error`](BlockCipher::Error) type can be
/// stored together behind `dyn BlockCipher<Error = E>` after initialization.
pub trait BlockCipher {
    /// The failure type returned by block processing.
    type Error: core::error::Error;

    /// Returns the block size in bytes.
    fn block_size(&self) -> usize;

    /// Processes one block and returns the number of bytes written.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Initializes an object from parameters of type `P`.
///
/// This trait is independent from [`BlockCipher`]. Consumers that need both
/// capabilities use `C: BlockCipher + BlockCipherInit<P>`. Keeping `P` as a
/// trait parameter lets one caller-owned parameter object flow through any
/// number of composing cipher layers.
pub trait BlockCipherInit<P: ?Sized> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the cipher for the selected transformation direction.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::boxed::Box;

    use super::{BlockCipher, BlockCipherInit};
    use crate::CipherDirection;

    const BLOCK_SIZE: usize = 4;

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
        type Error = crate::BlockError;

        fn block_size(&self) -> usize {
            BLOCK_SIZE
        }

        fn process_block(
            &mut self,
            input: &[u8],
            output: &mut [u8],
        ) -> Result<usize, crate::BlockError> {
            if input.len() < BLOCK_SIZE || output.len() < BLOCK_SIZE {
                return Err(crate::BlockError::BufferTooShort);
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

    impl BlockCipherInit<TestParams<'_>> for TestCipher {
        type Error = crate::InitError;

        fn init(
            &mut self,
            direction: CipherDirection,
            params: &TestParams<'_>,
        ) -> Result<(), crate::InitError> {
            let key_byte = params
                .key
                .first()
                .copied()
                .ok_or(crate::InitError::InvalidKeyLength(0))?;
            self.direction = direction;
            self.key_byte = key_byte;
            Ok(())
        }
    }

    #[test]
    fn initialized_ciphers_support_dynamic_dispatch_in_both_directions() {
        let params = TestParams { key: &[0x10] };
        let plaintext = [0x00, 0x7f, 0xf0, 0xff];

        let mut encryptor = TestCipher::new();
        let initializer: &mut dyn BlockCipherInit<TestParams<'_>, Error = crate::InitError> =
            &mut encryptor;
        initializer.init(CipherDirection::Encrypt, &params).unwrap();
        let mut encryptor: Box<dyn BlockCipher<Error = crate::BlockError>> = Box::new(encryptor);
        let mut ciphertext = [0_u8; BLOCK_SIZE];

        assert_eq!(encryptor.block_size(), BLOCK_SIZE);
        assert_eq!(
            encryptor.process_block(&plaintext, &mut ciphertext),
            Ok(BLOCK_SIZE)
        );

        let mut decryptor = TestCipher::new();
        decryptor.init(CipherDirection::Decrypt, &params).unwrap();
        let mut decryptor: Box<dyn BlockCipher<Error = crate::BlockError>> = Box::new(decryptor);
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
            Err(crate::BlockError::BufferTooShort)
        );
        assert_eq!(
            cipher.process_block(&[0_u8; BLOCK_SIZE], &mut [0_u8; BLOCK_SIZE - 1]),
            Err(crate::BlockError::BufferTooShort)
        );
    }

    #[test]
    fn initialization_can_use_the_shared_error_type() {
        let mut cipher = TestCipher::new();
        assert_eq!(
            cipher.init(CipherDirection::Encrypt, &TestParams { key: &[] }),
            Err(crate::InitError::InvalidKeyLength(0))
        );
    }
}
