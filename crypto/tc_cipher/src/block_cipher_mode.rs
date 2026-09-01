//! Block-cipher mode contract.

use crate::BlockCipher;

/// An initialized mode of operation over an underlying block cipher.
///
/// Mode initialization continues to use [`crate::BlockCipherInit`]. This
/// trait adds the mode-specific operations from Bouncy Castle's
/// `IBlockCipherMode` while remaining usable through `dyn BlockCipherMode`.
pub trait BlockCipherMode: BlockCipher {
    /// The block cipher wrapped by this mode.
    type Cipher: BlockCipher + ?Sized;

    /// Returns the underlying block cipher.
    fn underlying_cipher(&self) -> &Self::Cipher;

    /// Reports whether the mode can process a final partial block.
    fn is_partial_block_okay(&self) -> bool;

    /// Restores the mode state established by the most recent initialization.
    fn reset(&mut self);
}

#[cfg(test)]
mod tests {
    use super::BlockCipherMode;
    use crate::{BlockCipher, BlockError};

    struct TestCipher;

    impl BlockCipher for TestCipher {
        type Error = BlockError;

        fn block_size(&self) -> usize {
            4
        }

        fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            if input.len() < 4 || output.len() < 4 {
                return Err(BlockError::BufferTooShort);
            }
            output[..4].copy_from_slice(&input[..4]);
            Ok(4)
        }
    }

    struct TestMode {
        cipher: TestCipher,
        resets: usize,
    }

    impl BlockCipher for TestMode {
        type Error = BlockError;

        fn block_size(&self) -> usize {
            self.cipher.block_size()
        }

        fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            self.cipher.process_block(input, output)
        }
    }

    impl BlockCipherMode for TestMode {
        type Cipher = TestCipher;

        fn underlying_cipher(&self) -> &Self::Cipher {
            &self.cipher
        }

        fn is_partial_block_okay(&self) -> bool {
            false
        }

        fn reset(&mut self) {
            self.resets += 1;
        }
    }

    #[test]
    fn supports_dynamic_dispatch() {
        let mut concrete = TestMode {
            cipher: TestCipher,
            resets: 0,
        };
        let mode: &mut dyn BlockCipherMode<Error = BlockError, Cipher = TestCipher> = &mut concrete;

        assert_eq!(mode.block_size(), 4);
        assert_eq!(mode.underlying_cipher().block_size(), 4);
        assert!(!mode.is_partial_block_okay());
        mode.reset();
        assert_eq!(concrete.resets, 1);
    }
}
