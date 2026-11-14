use core::error::Error;
use core::marker::PhantomData;

use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, BufferedError};

use crate::cipher::{Cipher, CipherDirection};
use crate::params::{IvParams, KeyOwned, KeyWithIvOwned};
use crate::{AlgoError, ErrorKind, Params};

// The params of an engine's own that a row takes besides a bare key, as Bouncy Castle's
// CipherUtilities takes RC2Parameters besides a KeyParameter: Own<O> takes an O in ECB and a
// ParamsWithIvOwned<O> in the modes with an IV, and NoOwn takes none
pub(super) struct NoOwn;

#[cfg(any(
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024"
))]
pub(super) struct Own<O>(PhantomData<fn() -> O>);

// Inits a mode with an IV when params are the row's own params with an IV, and gives None when
// they are not. `iv_len` is the IV length the row requires, if it requires one
pub(super) trait OwnWithIv<C> {
    fn init(
        cipher: &mut C,
        direction: CipherDirection,
        params: &dyn Params,
        iv_len: Option<usize>,
    ) -> Option<Result<(), AlgoError>>;
}

// Inits ECB when params are the row's own params, and gives None when they are not
pub(super) trait OwnKey<C> {
    fn init(
        cipher: &mut C,
        direction: CipherDirection,
        params: &dyn Params,
    ) -> Option<Result<(), AlgoError>>;
}

impl<C> OwnWithIv<C> for NoOwn {
    fn init(
        _: &mut C,
        _: CipherDirection,
        _: &dyn Params,
        _: Option<usize>,
    ) -> Option<Result<(), AlgoError>> {
        None
    }
}

impl<C> OwnKey<C> for NoOwn {
    fn init(_: &mut C, _: CipherDirection, _: &dyn Params) -> Option<Result<(), AlgoError>> {
        None
    }
}

#[cfg(any(
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024"
))]
impl<C, O: 'static> OwnWithIv<C> for Own<O>
where
    C: BufferedCipherInit<crate::params::ParamsWithIvOwned<O>>,
    <C as BufferedCipherInit<crate::params::ParamsWithIvOwned<O>>>::Error:
        Error + Send + Sync + 'static,
{
    fn init(
        cipher: &mut C,
        direction: CipherDirection,
        params: &dyn Params,
        iv_len: Option<usize>,
    ) -> Option<Result<(), AlgoError>> {
        let params = params
            .as_any()
            .downcast_ref::<crate::params::ParamsWithIvOwned<O>>()?;
        if iv_len.is_some_and(|len| params.iv().len() != len) {
            return Some(Err(AlgoError::new(ErrorKind::InvalidParams)));
        }
        Some(cipher.init(direction, params).map_err(invalid_params))
    }
}

#[cfg(any(
    feature = "rc2",
    feature = "rc5",
    feature = "rc5-64",
    feature = "gost28147",
    feature = "threefish-256",
    feature = "threefish-512",
    feature = "threefish-1024"
))]
impl<C, O: 'static> OwnKey<C> for Own<O>
where
    C: BufferedCipherInit<O>,
    <C as BufferedCipherInit<O>>::Error: Error + Send + Sync + 'static,
{
    fn init(
        cipher: &mut C,
        direction: CipherDirection,
        params: &dyn Params,
    ) -> Option<Result<(), AlgoError>> {
        let params = params.as_any().downcast_ref::<O>()?;
        Some(cipher.init(direction, params).map_err(invalid_params))
    }
}

// Puts a buffered cipher, whatever its padding, behind Cipher. Its params are a KeyWithIvOwned.
// Unlike Bouncy Castle, a short IV is refused: padded with zeros, it could repeat a keystream
// without anyone noticing
// A mode under tc_buffered_cipher, keyed by a KeyWithIvOwned with an IV of one block, as CBC, CFB
// and OFB take it
// The second field is the engine's block in bytes, the IV CBC, CFB and OFB take: the block of the
// cipher under tc_buffered_cipher is a segment, a byte for CFB8
pub(super) struct Buffered<C, O = NoOwn>(
    pub(super) C,
    pub(super) usize,
    pub(super) PhantomData<fn() -> O>,
);

impl<C, O, E, I> BufferedCipher for Buffered<C, O>
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

impl<C, O, E, I> Cipher for Buffered<C, O>
where
    C: BufferedCipher<Error = BufferedError<E>> + BufferedCipherInit<KeyWithIvOwned, Error = I>,
    E: Error + Send + Sync + 'static,
    I: Error + Send + Sync + 'static,
    O: OwnWithIv<C>,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        if let Some(result) = O::init(&mut self.0, direction, params, Some(self.1)) {
            return result;
        }
        let params = downcast::<KeyWithIvOwned>(params)?;
        if params.iv().len() != self.1 {
            return Err(AlgoError::new(ErrorKind::InvalidParams));
        }
        self.0.init(direction, params).map_err(invalid_params)
    }
}

// ECB has no IV, so its params are a KeyOwned
// ECB, keyed by a KeyOwned, since it takes no IV
pub(super) struct Ecb<C, O = NoOwn>(pub(super) Buffered<C, O>);

impl<C, O, I> BufferedCipher for Ecb<C, O>
where
    Buffered<C, O>: BufferedCipher<Error = AlgoError>,
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

impl<C, O, I> Cipher for Ecb<C, O>
where
    Buffered<C, O>: BufferedCipher<Error = AlgoError>,
    C: BufferedCipherInit<KeyOwned, Error = I>,
    I: Error + Send + Sync + 'static,
    O: OwnKey<C>,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        if let Some(result) = O::init(&mut self.0.0, direction, params) {
            return result;
        }
        let params = downcast::<KeyOwned>(params)?;
        self.0.0.init(direction, params).map_err(invalid_params)
    }
}

// CTR, keyed by a KeyWithIvOwned whose IV tc_block_modes checks, since it may be shorter than a
// block
pub(super) struct Ctr<C, O = NoOwn>(pub(super) Buffered<C, O>);

impl<C, O, I> BufferedCipher for Ctr<C, O>
where
    Buffered<C, O>: BufferedCipher<Error = AlgoError>,
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

impl<C, O, I> Cipher for Ctr<C, O>
where
    Buffered<C, O>: BufferedCipher<Error = AlgoError>,
    C: BufferedCipherInit<KeyWithIvOwned, Error = I>,
    I: Error + Send + Sync + 'static,
    O: OwnWithIv<C>,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        if let Some(result) = O::init(&mut self.0.0, direction, params, None) {
            return result;
        }
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
