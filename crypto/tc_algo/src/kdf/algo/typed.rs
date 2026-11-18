use core::error::Error;
use core::marker::PhantomData;

use tc_asn1::Asn1Oid;
use tc_kdf::{KdfError, KdfInit};

use crate::kdf::{Kdf, KdfEntry};
use crate::{AlgoError, EntryBase, ErrorKind, Params};

// A row of a KDF over another row, a digest or a MAC: its names, OIDs, and how to make one
pub(super) struct Row {
    name: String,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    create: Box<dyn Fn() -> Box<dyn Kdf> + Send + Sync>,
}

impl Row {
    // `{kdf}-{name}`, and `{kdf}-{other}` for each other name the row underneath goes by, but
    // those that differ from the name in case alone, which finds the row anyway
    pub(super) fn boxed(
        kdf: &str,
        name: &str,
        others: &[&str],
        oids: Vec<Asn1Oid>,
        create: impl Fn() -> Box<dyn Kdf> + Send + Sync + 'static,
    ) -> Box<dyn KdfEntry> {
        let name = format!("{kdf}-{name}");
        let mut aliases: Vec<String> = Vec::new();
        for other in others {
            let alias = format!("{kdf}-{other}");
            if !alias.eq_ignore_ascii_case(&name)
                && !aliases
                    .iter()
                    .any(|known| known.eq_ignore_ascii_case(&alias))
            {
                aliases.push(alias);
            }
        }
        Box::new(Self {
            name,
            aliases,
            oids,
            create: Box::new(create),
        })
    }
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

impl KdfEntry for Row {
    fn create(&self) -> Box<dyn Kdf> {
        (self.create)()
    }
}

// A KDF of tc_kdf whose params are a P, behind the Kdf of this crate: params of another type are
// InvalidParams, and so is any failure of init, which comes from the params
#[allow(dead_code, reason = "unused when pbkdf2 is the only KDF on")]
pub(super) struct Typed<K, P> {
    kdf: K,
    params: PhantomData<fn() -> P>,
}

impl<K, P> Typed<K, P> {
    #[allow(dead_code, reason = "unused when pbkdf2 is the only KDF on")]
    pub(super) fn boxed(kdf: K) -> Box<dyn Kdf>
    where
        Self: Kdf + 'static,
    {
        Box::new(Self {
            kdf,
            params: PhantomData,
        })
    }
}

impl<K, P, E> tc_kdf::Kdf for Typed<K, P>
where
    K: tc_kdf::Kdf<Error = KdfError<E>>,
    E: Error + Send + Sync + 'static,
{
    type Error = AlgoError;

    // Before init it is NotInitialized; past the function's limit, DataLength
    fn generate_bytes(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.kdf.generate_bytes(output).map_err(|error| {
            let kind = match error {
                KdfError::NotInitialised => ErrorKind::NotInitialized,
                KdfError::OutputTooLong => ErrorKind::DataLength,
                _ => ErrorKind::InvalidParams,
            };
            AlgoError::with_source(kind, error)
        })
    }
}

impl<K, P, I> KdfInit<dyn Params> for Typed<K, P>
where
    K: KdfInit<P, Error = I>,
    P: 'static,
    I: Error + Send + Sync + 'static,
{
    type Error = AlgoError;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        let params = params
            .as_any()
            .downcast_ref::<P>()
            .ok_or(AlgoError::new(ErrorKind::InvalidParams))?;
        self.kdf
            .init(params)
            .map_err(|error| AlgoError::with_source(ErrorKind::InvalidParams, error))
    }
}

impl<K, P, E, I> Kdf for Typed<K, P>
where
    K: tc_kdf::Kdf<Error = KdfError<E>> + KdfInit<P, Error = I>,
    P: 'static,
    E: Error + Send + Sync + 'static,
    I: Error + Send + Sync + 'static,
{
}
