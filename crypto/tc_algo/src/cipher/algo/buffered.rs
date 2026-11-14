use core::error::Error;

use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, BufferedError};

use crate::cipher::{Cipher, CipherDirection};
use crate::params::{IvParams, KeyOwned, KeyWithIvOwned};
use crate::{AlgoError, ErrorKind, Params};

// Puts a buffered cipher, whatever its padding, behind Cipher. Its params are a KeyWithIvOwned.
// Unlike Bouncy Castle, a short IV is refused: padded with zeros, it could repeat a keystream
// without anyone noticing
// A mode under tc_buffered_cipher, keyed by a KeyWithIvOwned with an IV of one block, as CBC, CFB
// and OFB take it
pub(super) struct Buffered<C>(pub(super) C);

impl<C, E, I> BufferedCipher for Buffered<C>
where
    C: BufferedCipher<Error = BufferedError<E>> + BufferedCipherInit<KeyWithIvOwned, Error = I>,
    E: Error + Send + Sync + 'static,
    I: Error + Send + Sync + 'static,
{
    type Error = AlgoError;

    fn block_size(&self) -> usize {
        self.0.block_size()
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.update_output_len(input_len).map_err(algo_error)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.output_len(input_len).map_err(algo_error)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.process_bytes(input, output).map_err(algo_error)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.do_final(output).map_err(algo_error)
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

impl<C, E, I> Cipher for Buffered<C>
where
    C: BufferedCipher<Error = BufferedError<E>> + BufferedCipherInit<KeyWithIvOwned, Error = I>,
    E: Error + Send + Sync + 'static,
    I: Error + Send + Sync + 'static,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let params = downcast::<KeyWithIvOwned>(params)?;
        if params.iv().len() != self.0.block_size() {
            return Err(AlgoError::new(ErrorKind::InvalidParams));
        }
        self.0.init(direction, params).map_err(invalid_params)
    }
}

// ECB has no IV, so its params are a KeyOwned
// ECB, keyed by a KeyOwned, since it takes no IV
pub(super) struct Ecb<C>(pub(super) Buffered<C>);

impl<C, I> BufferedCipher for Ecb<C>
where
    Buffered<C>: Cipher,
    C: BufferedCipherInit<KeyOwned, Error = I>,
    I: Error + Send + Sync + 'static,
{
    type Error = AlgoError;

    fn block_size(&self) -> usize {
        self.0.block_size()
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.update_output_len(input_len)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.output_len(input_len)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.process_bytes(input, output)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.do_final(output)
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

impl<C, I> Cipher for Ecb<C>
where
    Buffered<C>: Cipher,
    C: BufferedCipherInit<KeyOwned, Error = I>,
    I: Error + Send + Sync + 'static,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let params = downcast::<KeyOwned>(params)?;
        self.0.0.init(direction, params).map_err(invalid_params)
    }
}

// CTR, keyed by a KeyWithIvOwned whose IV tc_block_modes checks, since it may be shorter than a
// block
pub(super) struct Ctr<C>(pub(super) Buffered<C>);

impl<C, I> BufferedCipher for Ctr<C>
where
    Buffered<C>: Cipher,
    C: BufferedCipherInit<KeyWithIvOwned, Error = I>,
    I: Error + Send + Sync + 'static,
{
    type Error = AlgoError;

    fn block_size(&self) -> usize {
        self.0.block_size()
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.update_output_len(input_len)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.output_len(input_len)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.process_bytes(input, output)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.do_final(output)
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

impl<C, I> Cipher for Ctr<C>
where
    Buffered<C>: Cipher,
    C: BufferedCipherInit<KeyWithIvOwned, Error = I>,
    I: Error + Send + Sync + 'static,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let params = downcast::<KeyWithIvOwned>(params)?;
        self.0.0.init(direction, params).map_err(invalid_params)
    }
}

pub(super) fn downcast<T: 'static>(params: &dyn Params) -> Result<&T, AlgoError> {
    params
        .as_any()
        .downcast_ref::<T>()
        .ok_or(AlgoError::new(ErrorKind::InvalidParams))
}

pub(super) fn invalid_params<E: Error + Send + Sync + 'static>(error: E) -> AlgoError {
    AlgoError::with_source(ErrorKind::InvalidParams, error)
}

pub(super) fn algo_error<E: Error + Send + Sync + 'static>(error: BufferedError<E>) -> AlgoError {
    let kind = match error {
        BufferedError::NotInitialized => ErrorKind::NotInitialized,
        BufferedError::CorruptPadding => ErrorKind::InvalidCiphertext,
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}
