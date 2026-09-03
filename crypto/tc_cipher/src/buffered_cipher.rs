//! Buffered byte-stream cipher contracts.

use crate::CipherDirection;

/// An initialized cipher that accepts input of any length.
///
/// This is the port of Bouncy Castle's `IBufferedCipher`. The layers below it
/// work in whole blocks; this one accumulates bytes, emits blocks as they fill,
/// and holds back whatever the finalization step still needs — the trailing
/// partial block, or a whole block when padding has to be removed from it.
///
/// The many `byte[]`, offset, and `Span` overloads of the C# interface collapse
/// into one method each: callers supply the output buffer and receive the
/// number of bytes written. `PaddingName`'s counterpart, the algorithm name, is
/// reported by implementing `tc_crypto::AlgorithmName`.
///
/// This trait contains only operations that can be dispatched through a trait
/// object. Initialization is provided independently by [`BufferedCipherInit`].
pub trait BufferedCipher {
    /// The failure type returned by buffered processing and finalization.
    type Error: core::error::Error;

    /// Returns the block size in bytes of the underlying cipher.
    ///
    /// Stream ciphers report zero, matching `GetBlockSize` in Bouncy Castle.
    fn block_size(&self) -> usize;

    /// Returns the output capacity required by one
    /// [`process_bytes`](Self::process_bytes) call for `input_len` additional
    /// bytes in the current state.
    ///
    /// This counts only the blocks that call can emit. Bytes still held in the
    /// buffer afterwards are reported by [`get_output_size`](Self::get_output_size).
    fn get_update_output_size(&self, input_len: usize) -> usize;

    /// Returns the output capacity required to process `input_len` additional
    /// bytes and then finalize in the current state.
    ///
    /// Padded encryption of an exact multiple of the block size needs one whole
    /// block more than the input, because padding always adds at least one byte
    /// and there is no room left in the last full block.
    fn get_output_size(&self, input_len: usize) -> usize;

    /// Processes one byte and returns the number of bytes written.
    ///
    /// Usually zero, since a single byte rarely completes a block.
    fn process_byte(&mut self, input: u8, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Processes `input` into `output` and returns the number of bytes written.
    ///
    /// `output` must hold at least [`get_update_output_size`](Self::get_update_output_size)
    /// bytes for this input length.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Finishes the operation and returns the number of bytes written.
    ///
    /// This is where padding is added or removed and where a trailing partial
    /// block is resolved. A failed call must not leave unverified plaintext in
    /// `output`.
    ///
    /// Whether a successful call can start another message without a fresh
    /// initialization follows the wrapped cipher. In particular, an AEAD
    /// encryptor may remain finalized to prevent key-and-nonce reuse.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Discards buffered input and restores the state established by the most
    /// recent initialization when the wrapped cipher permits it.
    ///
    /// An AEAD encryptor may remain finalized when restoring it would permit
    /// reuse of a key and nonce.
    fn reset(&mut self);
}

/// Initializes a buffered cipher from parameters of type `P`.
///
/// This trait is independent from [`BufferedCipher`]. Consumers that need both
/// capabilities use `C: BufferedCipher + BufferedCipherInit<P>`. Keeping `P` as
/// a trait parameter lets one caller-owned parameter object flow through any
/// number of composing cipher layers.
pub trait BufferedCipherInit<P: ?Sized> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the cipher for the selected transformation direction.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::boxed::Box;

    use super::{BufferedCipher, BufferedCipherInit};
    use crate::{BufferedError, CipherDirection, InitError};

    const BLOCK_SIZE: usize = 4;

    struct TestParams<'a> {
        key: &'a [u8],
    }

    /// 最小可用的緩衝層:湊滿 4 個位元組就 XOR 送出,尾巴留到 do_final。
    #[derive(Default)]
    struct TestBuffered {
        initialised: bool,
        mask: u8,
        buffer: [u8; BLOCK_SIZE],
        buffered: usize,
    }

    impl BufferedCipher for TestBuffered {
        type Error = BufferedError;

        fn block_size(&self) -> usize {
            BLOCK_SIZE
        }

        fn get_update_output_size(&self, input_len: usize) -> usize {
            let total = self.buffered + input_len;
            total - total % BLOCK_SIZE
        }

        fn get_output_size(&self, input_len: usize) -> usize {
            self.buffered + input_len
        }

        fn process_byte(&mut self, input: u8, output: &mut [u8]) -> Result<usize, Self::Error> {
            self.process_bytes(&[input], output)
        }

        fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
            if !self.initialised {
                return Err(BufferedError::NotInitialised);
            }

            let required = self.get_update_output_size(input.len());
            if output.len() < required {
                return Err(BufferedError::OutputTooShort {
                    required,
                    available: output.len(),
                });
            }

            let mut written = 0;
            for &byte in input {
                self.buffer[self.buffered] = byte ^ self.mask;
                self.buffered += 1;
                if self.buffered == BLOCK_SIZE {
                    output[written..written + BLOCK_SIZE].copy_from_slice(&self.buffer);
                    written += BLOCK_SIZE;
                    self.buffered = 0;
                }
            }

            Ok(written)
        }

        fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            if !self.initialised {
                return Err(BufferedError::NotInitialised);
            }
            if self.buffered != 0 {
                return Err(BufferedError::IncompleteLastBlock);
            }
            let _ = output;
            self.reset();
            Ok(0)
        }

        fn reset(&mut self) {
            self.buffer = [0; BLOCK_SIZE];
            self.buffered = 0;
        }
    }

    impl BufferedCipherInit<TestParams<'_>> for TestBuffered {
        type Error = InitError;

        fn init(
            &mut self,
            _direction: CipherDirection,
            params: &TestParams<'_>,
        ) -> Result<(), Self::Error> {
            self.mask = params
                .key
                .first()
                .copied()
                .ok_or(InitError::InvalidKeyLength(0))?;
            self.initialised = true;
            self.reset();
            Ok(())
        }
    }

    #[test]
    fn initialization_and_processing_support_dynamic_dispatch() {
        let mut concrete = TestBuffered::default();
        let initializer: &mut dyn BufferedCipherInit<TestParams<'_>, Error = InitError> =
            &mut concrete;
        initializer
            .init(CipherDirection::Encrypt, &TestParams { key: &[0xff] })
            .unwrap();

        let mut cipher: Box<dyn BufferedCipher<Error = BufferedError>> = Box::new(concrete);
        let mut output = [0_u8; 8];

        assert_eq!(cipher.block_size(), BLOCK_SIZE);
        // 只送 3 個位元組湊不滿一塊,什麼都不會吐出來。
        assert_eq!(cipher.get_update_output_size(3), 0);
        assert_eq!(cipher.process_bytes(&[1, 2, 3], &mut output), Ok(0));

        // 再送 1 個就滿了,整塊一次吐出。
        assert_eq!(cipher.get_update_output_size(1), BLOCK_SIZE);
        assert_eq!(cipher.process_byte(4, &mut output), Ok(BLOCK_SIZE));
        assert_eq!(output[..BLOCK_SIZE], [0xfe, 0xfd, 0xfc, 0xfb]);

        assert_eq!(cipher.do_final(&mut output), Ok(0));
    }

    #[test]
    fn processing_before_initialization_is_an_error() {
        let mut cipher = TestBuffered::default();

        assert_eq!(
            cipher.process_bytes(&[1], &mut [0_u8; 4]),
            Err(BufferedError::NotInitialised)
        );
        assert_eq!(
            cipher.do_final(&mut [0_u8; 4]),
            Err(BufferedError::NotInitialised)
        );
    }

    #[test]
    fn a_short_output_buffer_is_rejected() {
        let mut cipher = TestBuffered::default();
        cipher
            .init(CipherDirection::Encrypt, &TestParams { key: &[0xff] })
            .unwrap();

        assert_eq!(
            cipher.process_bytes(&[1, 2, 3, 4], &mut [0_u8; 3]),
            Err(BufferedError::OutputTooShort {
                required: 4,
                available: 3,
            })
        );
    }

    #[test]
    fn a_trailing_partial_block_is_reported_at_finalization() {
        let mut cipher = TestBuffered::default();
        cipher
            .init(CipherDirection::Encrypt, &TestParams { key: &[0xff] })
            .unwrap();
        cipher.process_bytes(&[1, 2, 3], &mut [0_u8; 4]).unwrap();

        assert_eq!(
            cipher.do_final(&mut [0_u8; 4]),
            Err(BufferedError::IncompleteLastBlock)
        );
    }
}
