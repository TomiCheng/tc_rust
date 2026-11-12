use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};

use super::classify::{Classify, to_algo_error};
use super::init_params::SymmetricParams;
use crate::AlgoError;

// For type erasure: a block cipher engine whose errors are already AlgoError, so the modes are
// built over one engine type whichever algorithm sits underneath
trait DynEngine:
    BlockCipher<Error = AlgoError> + BlockCipherInit<SymmetricParams, Error = AlgoError> + Send
{
}

impl<T> DynEngine for T where
    T: BlockCipher<Error = AlgoError> + BlockCipherInit<SymmetricParams, Error = AlgoError> + Send
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

impl<T> BlockCipherInit<SymmetricParams> for Mapped<T>
where
    T: BlockCipherInit<SymmetricParams>,
    T::Error: Classify + core::error::Error + Send + Sync + 'static,
{
    type Error = AlgoError;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &SymmetricParams,
    ) -> Result<(), AlgoError> {
        self.0.init(direction, params).map_err(to_algo_error)
    }
}

pub(super) struct AnyEngine(Box<dyn DynEngine>);

impl AnyEngine {
    #[allow(dead_code, reason = "unused when every block cipher feature is off")]
    pub(super) fn new<T>(engine: T) -> Self
    where
        T: BlockCipher + BlockCipherInit<SymmetricParams> + Send + 'static,
        <T as BlockCipher>::Error: Classify + core::error::Error + Send + Sync + 'static,
        <T as BlockCipherInit<SymmetricParams>>::Error:
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

impl BlockCipherInit<SymmetricParams> for AnyEngine {
    type Error = AlgoError;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &SymmetricParams,
    ) -> Result<(), AlgoError> {
        self.0.init(direction, params)
    }
}
