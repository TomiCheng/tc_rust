use core::error::Error;
use core::marker::PhantomData;

use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;
use tc_asym_encoding::EncodingError;
use tc_buffered_cipher::{BufferedCipher, BufferedError};

use crate::cipher::{Cipher, CipherDirection, CipherEntry};
use crate::{AlgoError, EntryBase, ErrorKind, Params};

pub(super) type Rand = fn() -> Box<dyn CryptoRng>;

// The row of an asymmetric cipher with one padding, as Bouncy Castle's CipherUtilities names it:
// `ALG//PADDING`, where the mode may also be NONE or ECB, and each padding in `paddings` names it
pub(super) fn row(
    algorithm: &'static str,
    name: &'static str,
    paddings: &[&str],
    oids: &[&str],
    rand: Rand,
    create: fn(Rand) -> Box<dyn Cipher>,
) -> Box<dyn CipherEntry> {
    let aliases = ["//", "/NONE/", "/ECB/"]
        .iter()
        .flat_map(|mode| {
            paddings
                .iter()
                .map(move |padding| format!("{algorithm}{mode}{padding}"))
        })
        .filter(|alias| alias != name)
        .collect();
    Box::new(Row {
        name,
        aliases,
        oids: oids
            .iter()
            .map(|dotted| dotted.parse().expect("a valid OID"))
            .collect(),
        rand,
        create,
    })
}

struct Row {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    rand: Rand,
    create: fn(Rand) -> Box<dyn Cipher>,
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
        (self.create)(self.rand)
    }
}

// Inits an asymmetric cipher with the key types of its algorithm, and refuses any other params
pub(super) trait Keys<C> {
    fn init(
        cipher: &mut C,
        direction: CipherDirection,
        params: &dyn Params,
    ) -> Result<(), AlgoError>;
}

// An asymmetric cipher behind Cipher, its key of the types K takes. One message is one block, so
// nothing comes out before do_final
pub(super) struct Asym<C, K>(pub(super) C, pub(super) PhantomData<fn() -> K>);

impl<C, K> Asym<C, K> {
    pub(super) fn new(cipher: C) -> Self {
        Self(cipher, PhantomData)
    }
}

impl<C, K, E> BufferedCipher for Asym<C, K>
where
    C: BufferedCipher<Error = BufferedError<E>>,
    E: Kind + Error + Send + Sync + 'static,
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

impl<C, K, E> Cipher for Asym<C, K>
where
    C: BufferedCipher<Error = BufferedError<E>>,
    E: Kind + Error + Send + Sync + 'static,
    K: Keys<C>,
{
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError> {
        K::init(&mut self.0, direction, params)
    }
}

pub(super) fn invalid_params<E: Error + Send + Sync + 'static>(error: E) -> AlgoError {
    AlgoError::with_source(ErrorKind::InvalidParams, error)
}

// The kind of an error of the engine or of an encoding over it
pub(super) trait Kind {
    fn kind(&self) -> ErrorKind;
}

impl<E: Kind> Kind for EncodingError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            EncodingError::Cipher(error) => error.kind(),
            EncodingError::NotInitialized => ErrorKind::NotInitialized,
            // A block that is not a valid PKCS#1 or OAEP encoding
            EncodingError::InvalidBlock => ErrorKind::InvalidCiphertext,
            _ => ErrorKind::DataLength,
        }
    }
}

fn algo_error<E: Kind + Error + Send + Sync + 'static>(error: BufferedError<E>) -> AlgoError {
    let kind = match &error {
        BufferedError::NotInitialized => ErrorKind::NotInitialized,
        BufferedError::Cipher(error) => error.kind(),
        _ => ErrorKind::DataLength,
    };
    AlgoError::with_source(kind, error)
}
