use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};

use super::classify::{Classify, to_algo_error};
use super::init_params::InitParams;
use crate::AlgoError;

// For type erasure: a block cipher engine whose errors are already AlgoError, so the modes are
// built over one engine type whichever algorithm sits underneath
trait DynEngine:
    BlockCipher<Error = AlgoError> + BlockCipherInit<InitParams, Error = AlgoError> + Send
{
}

impl<T> DynEngine for T where
    T: BlockCipher<Error = AlgoError> + BlockCipherInit<InitParams, Error = AlgoError> + Send
{
}

// A concrete engine with its errors turned into AlgoError
struct Mapped<T>(T);

impl<T> BlockCipher for Mapped<T>
where
    T: BlockCipher,
    T::Error: Classify + core::error::Error + Send + Sync + 'static,
{
    type Error = AlgoError;

    fn block_size(&self) -> usize {
        self.0.block_size()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.process_block(input, output).map_err(to_algo_error)
    }
}

impl<T> BlockCipherInit<InitParams> for Mapped<T>
where
    T: BlockCipherInit<InitParams>,
    T::Error: Classify + core::error::Error + Send + Sync + 'static,
{
    type Error = AlgoError;

    fn init(&mut self, direction: CipherDirection, params: &InitParams) -> Result<(), AlgoError> {
        self.0.init(direction, params).map_err(to_algo_error)
    }
}

pub(super) struct AnyEngine(Box<dyn DynEngine>);

impl AnyEngine {
    #[allow(dead_code, reason = "unused when every block cipher feature is off")]
    pub(super) fn new<T>(engine: T) -> Self
    where
        T: BlockCipher + BlockCipherInit<InitParams> + Send + 'static,
        <T as BlockCipher>::Error: Classify + core::error::Error + Send + Sync + 'static,
        <T as BlockCipherInit<InitParams>>::Error:
            Classify + core::error::Error + Send + Sync + 'static,
    {
        Self(Box::new(Mapped(engine)))
    }
}

impl BlockCipher for AnyEngine {
    type Error = AlgoError;

    fn block_size(&self) -> usize {
        self.0.block_size()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.0.process_block(input, output)
    }
}

impl BlockCipherInit<InitParams> for AnyEngine {
    type Error = AlgoError;

    fn init(&mut self, direction: CipherDirection, params: &InitParams) -> Result<(), AlgoError> {
        self.0.init(direction, params)
    }
}
