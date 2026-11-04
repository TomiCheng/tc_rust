use core::error::Error;

use tc_key_wrap::{KeyWithIvOptRef, KeyWithIvRef, KeyWrap, KeyWrapInit, WrapDirection};

use crate::cipher::classify::{Classify, to_algo_error};
use crate::{AlgoError, ErrorKind};

// For type erasure: every wrapper takes the same fields and gives the same error
pub(super) trait DynWrapper: Send + Sync {
    fn init(
        &mut self,
        direction: WrapDirection,
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<(), AlgoError>;
    fn wrapped_len(&self, input_len: usize) -> Result<usize, AlgoError>;
    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, AlgoError>;
    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError>;
    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError>;
}

type Init<T> = fn(&mut T, WrapDirection, &[u8], Option<&[u8]>) -> Result<(), AlgoError>;

// One wrapper engine behind the erased type. The engines differ only in the params init takes
#[allow(
    dead_code,
    reason = "unused when every key wrap feature is off, or their ciphers' are"
)]
pub(super) struct Mapped<T> {
    engine: T,
    init: Init<T>,
}

#[allow(
    dead_code,
    reason = "unused when every key wrap feature is off, or their ciphers' are"
)]
impl<T> Mapped<T> {
    pub(super) fn iv_optional(engine: T) -> Self
    where
        T: for<'a> KeyWrapInit<KeyWithIvOptRef<'a>>,
        for<'a> <T as KeyWrapInit<KeyWithIvOptRef<'a>>>::Error:
            Classify + Error + Send + Sync + 'static,
    {
        Self {
            engine,
            init: |engine, direction, key, iv| {
                engine
                    .init(direction, &KeyWithIvOptRef::new(key, iv))
                    .map_err(to_algo_error)
            },
        }
    }

    pub(super) fn iv_required(engine: T) -> Self
    where
        T: for<'a> KeyWrapInit<KeyWithIvRef<'a>>,
        for<'a> <T as KeyWrapInit<KeyWithIvRef<'a>>>::Error:
            Classify + Error + Send + Sync + 'static,
    {
        Self {
            engine,
            init: |engine, direction, key, iv| {
                let iv = iv.ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
                engine
                    .init(direction, &KeyWithIvRef::new(key, iv))
                    .map_err(to_algo_error)
            },
        }
    }
}

impl<T> DynWrapper for Mapped<T>
where
    T: KeyWrap + Send + Sync,
    T::Error: Classify + Error + Send + Sync + 'static,
{
    fn init(
        &mut self,
        direction: WrapDirection,
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<(), AlgoError> {
        (self.init)(&mut self.engine, direction, key, iv)
    }

    fn wrapped_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.engine.wrapped_len(input_len).map_err(to_algo_error)
    }

    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.engine
            .max_unwrapped_len(input_len)
            .map_err(to_algo_error)
    }

    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.engine.wrap_into(input, output).map_err(to_algo_error)
    }

    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.engine
            .unwrap_into(input, output)
            .map_err(to_algo_error)
    }
}
