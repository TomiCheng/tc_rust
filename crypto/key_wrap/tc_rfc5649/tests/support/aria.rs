//! Test-only bridge for wrappers that still use the legacy cipher traits.

use tc_block_cipher::{BlockCipher as _, BlockCipherInit as _};

pub struct AriaEngine(tc_aria::AriaEngine);

impl AriaEngine {
    pub fn new() -> Self {
        Self(tc_aria::AriaEngine::new())
    }
}

impl tc_crypto::AlgorithmName for AriaEngine {
    fn write_algo_name(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
        write!(out, "{}", self.0)
    }
}

impl<P: tc_params::KeyParams + ?Sized> tc_cipher::BlockCipherInit<P> for AriaEngine {
    type Error = tc_cipher::InitError;

    fn init(
        &mut self,
        direction: tc_cipher::CipherDirection,
        params: &P,
    ) -> Result<(), Self::Error> {
        let direction = match direction {
            tc_cipher::CipherDirection::Encrypt => tc_block_cipher::CipherDirection::Encrypt,
            tc_cipher::CipherDirection::Decrypt => tc_block_cipher::CipherDirection::Decrypt,
        };
        self.0
            .init(direction, &tc_block_cipher::KeyRef::new(params.key()))
            .map_err(|error| match error {
                tc_block_cipher::InitError::InvalidKeyLength(n) => {
                    tc_cipher::InitError::InvalidKeyLength(n)
                }
                other => panic!("unexpected ARIA initialization error: {other}"),
            })
    }
}

impl tc_cipher::BlockCipher for AriaEngine {
    type Error = tc_cipher::BlockError;

    fn block_size(&self) -> usize {
        self.0.block_size()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.0
            .process_block(input, output)
            .map_err(|error| match error {
                tc_block_cipher::BlockError::NotInitialised => {
                    tc_cipher::BlockError::NotInitialised
                }
                tc_block_cipher::BlockError::BufferTooShort => {
                    tc_cipher::BlockError::BufferTooShort
                }
                other => panic!("unexpected ARIA processing error: {other}"),
            })
    }
}
