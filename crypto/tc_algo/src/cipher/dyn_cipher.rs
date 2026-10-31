use core::marker::PhantomData;

use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, CipherDirection};

use super::classify::{Classify, to_algo_error};
use super::init_params::{InitParams, InitPart};
use crate::{AlgoError, ErrorKind};

// For type erasure: every cipher of the table, with its errors turned into AlgoError, takes the
// InitParams its entry built, and is Send so AnyCipher can move between threads
pub(super) trait DynCipher:
    BufferedCipher<Error = AlgoError> + BufferedCipherInit<InitParams, Error = AlgoError> + Send
{
}

impl<T> DynCipher for T where
    T: BufferedCipher<Error = AlgoError> + BufferedCipherInit<InitParams, Error = AlgoError> + Send
{
}

// A concrete buffered cipher that takes the part P of InitParams, with its errors turned into
// AlgoError
pub(super) struct Mapped<T, P: ?Sized>(T, PhantomData<fn(&P)>);

impl<T, P: ?Sized> Mapped<T, P> {
    pub(super) fn new(cipher: T) -> Self {
        Self(cipher, PhantomData)
    }
}

impl<T, P: ?Sized> BufferedCipher for Mapped<T, P>
where
    T: BufferedCipher,
    T::Error: Classify + core::error::Error + Send + Sync + 'static,
{
    type Error = AlgoError;

    fn block_size(&self) -> usize {
        self.0.block_size()
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.update_output_len(input_len).map_err(to_algo_error)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.0.output_len(input_len).map_err(to_algo_error)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.process_bytes(input, output).map_err(to_algo_error)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.do_final(output).map_err(to_algo_error)
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

impl<T, P> BufferedCipherInit<InitParams> for Mapped<T, P>
where
    T: BufferedCipherInit<P>,
    T::Error: Classify + core::error::Error + Send + Sync + 'static,
    P: InitPart + ?Sized,
{
    type Error = AlgoError;

    fn init(&mut self, direction: CipherDirection, params: &InitParams) -> Result<(), AlgoError> {
        let params = P::part(params).ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.0.init(direction, params).map_err(to_algo_error)
    }
}
