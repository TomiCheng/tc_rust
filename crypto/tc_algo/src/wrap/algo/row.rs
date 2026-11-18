use core::error::Error;
use core::marker::PhantomData;

use tc_asn1::Asn1Oid;
use tc_block_cipher::KeyParams;
use tc_block_modes::KeyWithIvOwned;
use tc_key_wrap::{KeyWrap, KeyWrapError, KeyWrapInit, WrapDirection as KeyWrapDirection};
use tc_zeroize::Zeroize;

use crate::params::key::KeyOwned;
use crate::wrap::{WrapDirection, Wrapper, WrapperEntry};
use crate::{AlgoError, EntryBase, ErrorKind, Params};

// What a row gives its tc_key_wrap engine, from the row's params
pub(super) trait FromParams: Sized {
    fn from_params(params: &dyn Params) -> Result<Self, AlgoError>;
}

// The KEK, and the IV of a KeyWithIvOwned, without which RFC 3394 and RFC 5649 take the standard IV
pub(super) struct WrapKey {
    key: Vec<u8>,
    iv: Option<Vec<u8>>,
}

// The KEK and the IV, which RFC 3211 needs
pub(super) struct WrapKeyWithIv(WrapKey);

impl FromParams for WrapKey {
    fn from_params(params: &dyn Params) -> Result<Self, AlgoError> {
        WrapKey::new(params, false)
    }
}

impl FromParams for WrapKeyWithIv {
    fn from_params(params: &dyn Params) -> Result<Self, AlgoError> {
        WrapKey::new(params, true).map(WrapKeyWithIv)
    }
}

impl WrapKey {
    fn new(params: &dyn Params, iv_required: bool) -> Result<Self, AlgoError> {
        let params = params.as_any();
        let key = if let Some(params) = params.downcast_ref::<KeyOwned>() {
            WrapKey {
                key: params.key().to_vec(),
                iv: None,
            }
        } else if let Some(params) = params.downcast_ref::<KeyWithIvOwned>() {
            WrapKey {
                key: KeyParams::key(params).to_vec(),
                iv: Some(tc_block_modes::IvParams::iv(params).to_vec()),
            }
        } else {
            return Err(AlgoError::new(ErrorKind::InvalidParams));
        };
        if iv_required && key.iv.is_none() {
            return Err(AlgoError::new(ErrorKind::InvalidParams));
        }
        Ok(key)
    }
}

impl Drop for WrapKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl KeyParams for WrapKey {
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl tc_key_wrap::IvOptParams for WrapKey {
    fn iv_opt(&self) -> Option<&[u8]> {
        self.iv.as_deref()
    }
}

impl KeyParams for WrapKeyWithIv {
    fn key(&self) -> &[u8] {
        &self.0.key
    }
}

impl tc_key_wrap::IvParams for WrapKeyWithIv {
    fn iv(&self) -> &[u8] {
        self.0.iv.as_deref().unwrap_or_default()
    }
}

// A tc_key_wrap engine under the Wrapper of tc_algo: its params come as dyn Params, and its errors
// as AlgoError
pub(super) struct RowWrap<W, K> {
    wrap: W,
    key: PhantomData<fn() -> K>,
}

impl<W, K> RowWrap<W, K> {
    pub(super) fn new(wrap: W) -> Self {
        Self {
            wrap,
            key: PhantomData,
        }
    }
}

impl<W, K, E> KeyWrap for RowWrap<W, K>
where
    W: KeyWrap<Error = KeyWrapError<E>>,
    E: Error + Send + Sync + 'static,
{
    type Error = AlgoError;

    fn wrapped_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.wrap.wrapped_len(input_len).map_err(algo_error)
    }

    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, AlgoError> {
        self.wrap.max_unwrapped_len(input_len).map_err(algo_error)
    }

    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.wrap.wrap_into(input, output).map_err(algo_error)
    }

    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError> {
        self.wrap.unwrap_into(input, output).map_err(algo_error)
    }
}

impl<W, K> KeyWrapInit<dyn Params> for RowWrap<W, K>
where
    K: FromParams,
    W: KeyWrapInit<K>,
    W::Error: Error + Send + Sync + 'static,
{
    type Error = AlgoError;

    fn init(&mut self, direction: WrapDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let key = K::from_params(params)?;
        let direction = match direction {
            WrapDirection::Wrap => KeyWrapDirection::Wrap,
            WrapDirection::Unwrap => KeyWrapDirection::Unwrap,
        };
        self.wrap
            .init(direction, &key)
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }
}

impl<W, K, E> Wrapper for RowWrap<W, K>
where
    K: FromParams,
    W: KeyWrap<Error = KeyWrapError<E>> + KeyWrapInit<K>,
    E: Error + Send + Sync + 'static,
    <W as KeyWrapInit<K>>::Error: Error + Send + Sync + 'static,
{
}

fn algo_error<E: Error + Send + Sync + 'static>(error: KeyWrapError<E>) -> AlgoError {
    let kind = match error {
        KeyWrapError::NotInitialized
        | KeyWrapError::NotForWrapping
        | KeyWrapError::NotForUnwrapping => ErrorKind::NotInitialized,
        KeyWrapError::IntegrityCheckFailed => ErrorKind::InvalidCiphertext,
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}

pub(super) type Create = Box<dyn Fn() -> Box<dyn Wrapper> + Send + Sync>;

// A row by its name, aliases and OIDs
pub(super) struct Row {
    name: String,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    create: Create,
}

pub(super) fn row(
    name: &str,
    aliases: &[&str],
    oids: &[&str],
    create: Create,
) -> Box<dyn WrapperEntry> {
    Box::new(Row {
        name: name.to_string(),
        aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
        oids: oids
            .iter()
            .map(|dotted| dotted.parse().expect("a valid OID"))
            .collect(),
        create,
    })
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        &self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl WrapperEntry for Row {
    fn create(&self) -> Box<dyn Wrapper> {
        (self.create)()
    }
}
