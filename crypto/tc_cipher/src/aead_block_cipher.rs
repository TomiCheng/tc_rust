//! Authenticated block-cipher construction contract.

use crate::{AeadCipher, BlockCipher};

/// An authenticated-encryption construction built on a block cipher.
///
/// Processing and finalization come from [`AeadCipher`]. Initialization
/// continues to use [`crate::AeadCipherInit`]. This trait identifies the
/// underlying block cipher used by constructions such as GCM, CCM, EAX, and
/// OCB.
pub trait AeadBlockCipher: AeadCipher {
    /// The block cipher wrapped by this AEAD construction.
    type Cipher: BlockCipher + ?Sized;

    /// Returns the underlying block cipher's block size in bytes.
    fn block_size(&self) -> usize {
        self.underlying_cipher().block_size()
    }

    /// Returns the underlying block cipher.
    fn underlying_cipher(&self) -> &Self::Cipher;
}

#[cfg(test)]
mod tests {
    use super::AeadBlockCipher;
    use crate::{AeadCipher, AeadError, BlockCipher, BlockError};

    struct TestBlockCipher;

    impl BlockCipher for TestBlockCipher {
        type Error = BlockError;

        fn block_size(&self) -> usize {
            16
        }

        fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            if input.len() < 16 || output.len() < 16 {
                return Err(BlockError::BufferTooShort);
            }
            output[..16].copy_from_slice(&input[..16]);
            Ok(16)
        }
    }

    struct TestAeadBlockCipher {
        cipher: TestBlockCipher,
    }

    impl AeadCipher for TestAeadBlockCipher {
        type Error = AeadError;

        fn process_aad_bytes(&mut self, _input: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            if output.len() < input.len() {
                return Err(AeadError::OutputTooShort {
                    required: input.len(),
                    available: output.len(),
                });
            }
            output[..input.len()].copy_from_slice(input);
            Ok(input.len())
        }

        fn do_final(&mut self, _output: &mut [u8]) -> Result<usize, Self::Error> {
            Ok(0)
        }

        fn mac(&self) -> Option<&[u8]> {
            None
        }

        fn get_update_output_size(&self, input_len: usize) -> usize {
            input_len
        }

        fn get_output_size(&self, input_len: usize) -> usize {
            input_len
        }
    }

    impl AeadBlockCipher for TestAeadBlockCipher {
        type Cipher = TestBlockCipher;

        fn underlying_cipher(&self) -> &Self::Cipher {
            &self.cipher
        }
    }

    #[test]
    fn supports_dynamic_dispatch() {
        let concrete = TestAeadBlockCipher {
            cipher: TestBlockCipher,
        };
        let cipher: &dyn AeadBlockCipher<Error = AeadError, Cipher = TestBlockCipher> = &concrete;

        assert_eq!(cipher.block_size(), 16);
        assert_eq!(cipher.underlying_cipher().block_size(), 16);
    }
}
