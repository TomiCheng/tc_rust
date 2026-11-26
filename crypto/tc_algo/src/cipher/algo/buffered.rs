use core::error::Error;
use core::marker::PhantomData;

use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, BufferedError};

use crate::cipher::{Cipher, CipherDirection};
use crate::params::{cipher::IvParams, cipher::KeyWithIvOwned, key::KeyOwned};
use crate::{AlgoError, ErrorKind, Params};

// The params of an engine's own that a row takes besides a bare key, as Bouncy Castle's
// CipherUtilities takes RC2Parameters besides a KeyParameter: Own<O> takes an O in ECB and a
// ParamsWithIvOwned<O> in the modes with an IV, and NoOwn takes none
pub(super) struct NoOwn;

#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
pub(super) struct Own<O>(PhantomData<fn() -> O>);

// Which own params a CTS row in CBC takes: tc_cts_modes takes params with an IV through IvParams
// and gives them to the engine whole, so the own params reach it in an IvView, which Keyed opens
pub(super) trait CtsOwn {
    type Cts;
}

impl CtsOwn for NoOwn {
    type Cts = NoOwn;
}

#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
impl<O> CtsOwn for Own<O> {
    type Cts = OwnViaIv<O>;
}

// The engine's own params and their IV, borrowed, as a type of this crate that implements
// IvParams
#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
pub(super) struct IvView<'a, O> {
    pub(super) params: &'a O,
    iv: &'a [u8],
}

#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
impl<O> IvParams for IvView<'_, O> {
    fn iv(&self) -> &[u8] {
        self.iv
    }
}

// The one place that opens params with an IV. It gives the row's own params O and the IV of a
// ParamsWithIvOwned<O>, or of a ParamsWithIvOwned<Arc<dyn Params>> whose inner params are an O,
// and None for anything else
#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
pub(super) fn own_and_iv<O: 'static>(params: &dyn Params) -> Option<(&O, &[u8])> {
    if let Some(params) = params
        .as_any()
        .downcast_ref::<tc_block_modes::ParamsWithIvOwned<O>>()
    {
        return Some((params.params(), params.iv()));
    }
    let shared = params
        .as_any()
        .downcast_ref::<tc_block_modes::ParamsWithIvOwned<std::sync::Arc<dyn Params>>>()?;
    let own = shared.params().as_any().downcast_ref::<O>()?;
    Some((own, shared.iv()))
}

// The own params O in a ParamsWithIvOwned<O>, given to the cipher as an IvView
#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
pub(super) struct OwnViaIv<O>(PhantomData<fn() -> O>);

#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
impl<C, O: 'static> OwnWithIv<C> for OwnViaIv<O>
where
    C: for<'a> BufferedCipherInit<
            IvView<'a, O>,
            Error = tc_block_modes::BlockModeInitError<tc_block_cipher::InitError>,
        >,
{
    fn init(
        cipher: &mut C,
        direction: CipherDirection,
        params: &dyn Params,
        iv_len: Option<usize>,
    ) -> Option<Result<(), AlgoError>> {
        let (own, iv) = own_and_iv::<O>(params)?;
        if iv_len.is_some_and(|len| iv.len() != len) {
            return Some(Err(AlgoError::new(ErrorKind::InvalidParams)));
        }
        let view = IvView { params: own, iv };
        Some(cipher.init(direction, &view).map_err(invalid_params))
    }
}

// The one place that opens a bare key with an IV. It gives the key bytes and the IV of a
// KeyWithIvOwned, of a ParamsWithIvOwned<KeyOwned>, or of a ParamsWithIvOwned of a Box or an Arc of
// dyn Params whose inner params are a KeyOwned, and None for anything else
pub(super) fn key_and_iv(params: &dyn Params) -> Option<(&[u8], &[u8])> {
    use tc_block_cipher::KeyParams;
    use tc_block_modes::ParamsWithIvOwned;
    let any = params.as_any();
    if let Some(params) = any.downcast_ref::<KeyWithIvOwned>() {
        return Some((params.key(), params.iv()));
    }
    if let Some(params) = any.downcast_ref::<ParamsWithIvOwned<KeyOwned>>() {
        return Some((params.params().key(), params.iv()));
    }
    let (inner, iv): (&dyn Params, &[u8]) =
        if let Some(params) = any.downcast_ref::<ParamsWithIvOwned<Box<dyn Params>>>() {
            (params.params().as_ref(), params.iv())
        } else {
            let params = any.downcast_ref::<ParamsWithIvOwned<std::sync::Arc<dyn Params>>>()?;
            (params.params().as_ref(), params.iv())
        };
    let key = inner.as_any().downcast_ref::<KeyOwned>()?;
    Some((key.key(), iv))
}

// A key and an IV borrowed from a ParamsWithIvOwned of a KeyOwned, which every mode and
// CTS take through KeyParams and IvParams, with no copy of the key
pub(super) struct KeyIvView<'a> {
    key: &'a [u8],
    iv: &'a [u8],
}

impl tc_block_cipher::KeyParams for KeyIvView<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl IvParams for KeyIvView<'_> {
    fn iv(&self) -> &[u8] {
        self.iv
    }
}

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

#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
impl<C, O: 'static, R> OwnWithIv<C> for Own<O>
where
    C: for<'a> BufferedCipherInit<tc_block_modes::ParamsWithIvRef<'a, O>, Error = R>,
    R: Error + Send + Sync + 'static,
{
    fn init(
        cipher: &mut C,
        direction: CipherDirection,
        params: &dyn Params,
        iv_len: Option<usize>,
    ) -> Option<Result<(), AlgoError>> {
        let (own, iv) = own_and_iv::<O>(params)?;
        if iv_len.is_some_and(|len| iv.len() != len) {
            return Some(Err(AlgoError::new(ErrorKind::InvalidParams)));
        }
        let view = tc_block_modes::ParamsWithIvRef::new(own, iv);
        Some(cipher.init(direction, &view).map_err(invalid_params))
    }
}

#[cfg(any(feature = "rc-cipher", feature = "gost28147", feature = "threefish"))]
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

impl<C, O, E, I, R> Cipher for Buffered<C, O>
where
    C: BufferedCipher<Error = BufferedError<E>>
        + BufferedCipherInit<KeyWithIvOwned, Error = I>
        + for<'a> BufferedCipherInit<KeyIvView<'a>, Error = R>,
    E: Error + Send + Sync + 'static,
    I: Error + Send + Sync + 'static,
    R: Error + Send + Sync + 'static,
    O: OwnWithIv<C>,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        if let Some(result) = O::init(&mut self.0, direction, params, Some(self.1)) {
            return result;
        }
        // A bare key with an IV, in any of the shapes key_and_iv knows, lent with no copy
        let (key, iv) = key_and_iv(params).ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        if iv.len() != self.1 {
            return Err(AlgoError::new(ErrorKind::InvalidParams));
        }
        self.0
            .init(direction, &KeyIvView { key, iv })
            .map_err(invalid_params)
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

impl<C, O, I, R> Cipher for Ctr<C, O>
where
    Buffered<C, O>: BufferedCipher<Error = AlgoError>,
    C: BufferedCipherInit<KeyWithIvOwned, Error = I>
        + for<'a> BufferedCipherInit<KeyIvView<'a>, Error = R>,
    I: Error + Send + Sync + 'static,
    R: Error + Send + Sync + 'static,
    O: OwnWithIv<C>,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        if let Some(result) = O::init(&mut self.0.0, direction, params, None) {
            return result;
        }
        // A bare key with an IV, in any of the shapes key_and_iv knows, lent with no copy
        let (key, iv) = key_and_iv(params).ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.0
            .0
            .init(direction, &KeyIvView { key, iv })
            .map_err(invalid_params)
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
