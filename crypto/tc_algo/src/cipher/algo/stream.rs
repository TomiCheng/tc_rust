use tc_asn1::Asn1Oid;
use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, BufferedError, BufferedStreamCipher};
#[cfg(any(feature = "rc4", feature = "isaac"))]
use tc_stream_cipher::KeyRef;
#[cfg(any(
    feature = "chacha",
    feature = "xchacha20",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "hc128",
    feature = "hc256",
))]
use tc_stream_cipher::KeyWithIvRef;
use tc_stream_cipher::StreamError;

use crate::cipher::{Cipher, CipherDirection, CipherEntry};
#[cfg(any(feature = "rc4", feature = "isaac"))]
use crate::params::KeyOwned;
use crate::params::KeyParams;
#[cfg(any(
    feature = "chacha",
    feature = "xchacha20",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "hc128",
    feature = "hc256",
))]
use crate::params::{IvParams, KeyWithIvOwned};
use crate::{AlgoError, EntryBase, ErrorKind, Params};

// The row of one stream cipher, named after the first of `names` with the others as aliases
pub(super) fn stream_row(
    names: &[&'static str],
    oids: &[&str],
    create: fn() -> Box<dyn Cipher>,
) -> Box<dyn CipherEntry> {
    Box::new(Row {
        name: names[0],
        aliases: names[1..].iter().map(|name| name.to_string()).collect(),
        oids: oids
            .iter()
            .map(|dotted| dotted.parse().expect("a valid OID"))
            .collect(),
        create,
    })
}

struct Row {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    create: fn() -> Box<dyn Cipher>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl CipherEntry for Row {
    fn create(&self) -> Box<dyn Cipher> {
        (self.create)()
    }
}

#[cfg(any(
    feature = "chacha",
    feature = "xchacha20",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "hc128",
    feature = "hc256",
))]
// A stream cipher keyed by a KeyWithIvOwned: a key and a nonce, as the block modes with an IV
pub(super) struct Nonced<E>(pub(super) BufferedStreamCipher<E>);

#[cfg(any(feature = "rc4", feature = "isaac"))]
// A stream cipher keyed by a KeyOwned alone, as RC4 and ISAAC, which take no nonce
pub(super) struct Keyed<E>(pub(super) BufferedStreamCipher<E>);

macro_rules! buffered {
    ($wrapper:ident) => {
        impl<E> BufferedCipher for $wrapper<E>
        where
            BufferedStreamCipher<E>: BufferedCipher<Error = BufferedError<StreamError>>,
        {
            type Error = AlgoError;

            // Zero, as for every stream cipher
            fn block_size(&self) -> usize {
                self.0.block_size()
            }

            fn update_output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
                self.0.update_output_len(input_len).map_err(algo_error)
            }

            fn output_len(&self, input_len: usize) -> Result<usize, AlgoError> {
                self.0.output_len(input_len).map_err(algo_error)
            }

            fn process_bytes(
                &mut self,
                input: &[u8],
                output: &mut [u8],
            ) -> Result<usize, AlgoError> {
                self.0.process_bytes(input, output).map_err(algo_error)
            }

            fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
                self.0.do_final(output).map_err(algo_error)
            }

            fn reset(&mut self) {
                self.0.reset();
            }
        }
    };
}

#[cfg(any(
    feature = "chacha",
    feature = "xchacha20",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "hc128",
    feature = "hc256",
))]
buffered!(Nonced);
#[cfg(any(feature = "rc4", feature = "isaac"))]
buffered!(Keyed);

#[cfg(any(
    feature = "chacha",
    feature = "xchacha20",
    feature = "vmpc",
    feature = "vmpc-ksa3",
    feature = "salsa20",
    feature = "xsalsa20",
    feature = "hc128",
    feature = "hc256",
))]
impl<E, I> Cipher for Nonced<E>
where
    BufferedStreamCipher<E>: BufferedCipher<Error = BufferedError<StreamError>>
        + for<'a> BufferedCipherInit<KeyWithIvRef<'a>, Error = I>,
    I: core::error::Error + Send + Sync + 'static,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<KeyWithIvOwned>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.0
            .init(direction, &KeyWithIvRef::new(params.key(), params.iv()))
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }
}

#[cfg(any(feature = "rc4", feature = "isaac"))]
impl<E, I> Cipher for Keyed<E>
where
    BufferedStreamCipher<E>: BufferedCipher<Error = BufferedError<StreamError>>
        + for<'a> BufferedCipherInit<KeyRef<'a>, Error = I>,
    I: core::error::Error + Send + Sync + 'static,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<KeyOwned>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.0
            .init(direction, &KeyRef::new(params.key()))
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }
}

fn algo_error(error: BufferedError<StreamError>) -> AlgoError {
    let kind = match error {
        BufferedError::NotInitialized => ErrorKind::NotInitialized,
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}
