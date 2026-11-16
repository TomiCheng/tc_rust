use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;

use crate::generate::{KeyPairGenerator, KeyPairGeneratorEntry};
use crate::{AlgoError, EntryBase, ErrorKind, Params};

// A new key pair, public then private
pub(super) type Pair = Result<(Box<dyn Params>, Box<dyn Params>), AlgoError>;

// What init makes of the params: the domain or parameter set of the keys, generated if need be
pub(super) type Prepare<P> = fn(&dyn Params, &mut dyn CryptoRng) -> Result<P, AlgoError>;

// A new pair over the domain or parameter set
pub(super) type Generate<P> = fn(&mut dyn CryptoRng, &P) -> Pair;

// The row of a key pair generator whose keys are over a domain or parameter set P: init makes P of
// the params, and generate makes a pair over it, as often as asked. A row with a default P needs no
// init
pub(super) struct Row<P> {
    pub(super) name: &'static str,
    pub(super) aliases: Vec<String>,
    pub(super) oids: Vec<Asn1Oid>,
    pub(super) rand: fn() -> Box<dyn CryptoRng>,
    pub(super) default: Option<fn() -> P>,
    pub(super) prepare: Prepare<P>,
    pub(super) generate: Generate<P>,
}

impl<P> Row<P> {
    pub(super) fn new(
        name: &'static str,
        aliases: &[&str],
        oids: &[&str],
        rand: fn() -> Box<dyn CryptoRng>,
        prepare: Prepare<P>,
        generate: Generate<P>,
    ) -> Self {
        Self {
            name,
            aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
            oids: oids
                .iter()
                .map(|dotted| dotted.parse().expect("a valid OID"))
                .collect(),
            rand,
            default: None,
            prepare,
            generate,
        }
    }

    #[allow(dead_code, reason = "used by Ed25519 and Ed448 alone")]
    pub(super) fn with_default(mut self, default: fn() -> P) -> Self {
        self.default = Some(default);
        self
    }
}

impl<P: 'static> EntryBase for Row<P> {
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

impl<P: 'static> KeyPairGeneratorEntry for Row<P> {
    fn create(&self) -> Box<dyn KeyPairGenerator> {
        Box::new(Generator {
            rand: (self.rand)(),
            params: self.default.map(|default| default()),
            prepare: self.prepare,
            generate: self.generate,
        })
    }
}

struct Generator<P> {
    rand: Box<dyn CryptoRng>,
    params: Option<P>,
    prepare: Prepare<P>,
    generate: Generate<P>,
}

impl<P> tc_asym_cipher::KeyPairGenerator for Generator<P> {
    type PublicKey = Box<dyn Params>;
    type PrivateKey = Box<dyn Params>;
    type Error = AlgoError;

    fn generate_key_pair(&mut self) -> Pair {
        let params = self
            .params
            .as_ref()
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))?;
        (self.generate)(self.rand.as_mut(), params)
    }
}

impl<P> tc_asym_cipher::KeyPairGeneratorInit<dyn Params> for Generator<P> {
    type Error = AlgoError;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        self.params = None;
        self.params = Some((self.prepare)(params, self.rand.as_mut())?);
        Ok(())
    }
}

impl<P> KeyPairGenerator for Generator<P> {}

pub(super) fn invalid_params<E: core::error::Error + Send + Sync + 'static>(error: E) -> AlgoError {
    AlgoError::with_source(ErrorKind::InvalidParams, error)
}

// The params, when they are of the type T
#[allow(dead_code, reason = "unused by Ed25519 and Ed448 alone")]
pub(super) fn downcast<T: Clone + 'static>(params: &dyn Params) -> Option<T> {
    params.as_any().downcast_ref::<T>().cloned()
}

// A row that takes no params refuses any
#[allow(dead_code, reason = "used by Ed25519 and Ed448 alone")]
pub(super) fn refuse<P>(_params: &dyn Params, _rand: &mut dyn CryptoRng) -> Result<P, AlgoError> {
    Err(AlgoError::new(ErrorKind::InvalidParams))
}
