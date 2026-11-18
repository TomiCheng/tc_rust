use core::error::Error;
use std::sync::Arc;

use tc_asn1::Asn1Oid;
use tc_signer::SignerInit;

use crate::digest::DigestEntry;
use crate::signer::{Signer, SignerEntry};
use crate::{AlgoError, DefaultAlgoContext, EntryBase, ErrorKind, Params};

// The kind of AlgoError an error of a signer of tc_rsa_signer, tc_dsa or tc_sm2 is
pub(super) trait Kind {
    fn kind(&self) -> ErrorKind;
}

// A signer of a row, keyed: what each call of the row's Signer goes to
pub(super) trait Inner {
    fn max_signature_size(&self) -> usize;
    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError>;
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, AlgoError>;
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, AlgoError>;
    fn reset(&mut self);
}

impl<S> Inner for S
where
    S: tc_signer::Signer,
    S::Error: Kind + Error + Send + Sync + 'static,
{
    fn max_signature_size(&self) -> usize {
        tc_signer::Signer::max_signature_size(self)
    }

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        tc_signer::Signer::update(self, input).map_err(algo_error)
    }

    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        tc_signer::Signer::generate_signature(self, output).map_err(algo_error)
    }

    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, AlgoError> {
        tc_signer::Signer::verify_signature(self, signature).map_err(algo_error)
    }

    fn reset(&mut self) {
        tc_signer::Signer::reset(self);
    }
}

fn algo_error<E: Kind + Error + Send + Sync + 'static>(error: E) -> AlgoError {
    AlgoError::with_source(error.kind(), error)
}

pub(super) fn invalid_params<E: Error + Send + Sync + 'static>(error: E) -> AlgoError {
    AlgoError::with_source(ErrorKind::InvalidParams, error)
}

// Keys a signer with the params of its type, and gives it as an Inner
pub(super) fn keyed<S, P>(mut signer: S, params: &P) -> Result<Box<dyn Inner>, AlgoError>
where
    S: SignerInit<P> + Inner + 'static,
    S::Error: Error + Send + Sync + 'static,
    P: ?Sized,
{
    signer.init(params).map_err(invalid_params)?;
    Ok(Box::new(signer))
}

// What builds a row's signer from its params, keyed: the signer to sign with a private key and to
// verify with a public one. It is built at init, as the params decide its type, such as the curve
pub(super) type Make = Arc<dyn Fn(&dyn Params) -> Result<Box<dyn Inner>, AlgoError> + Send + Sync>;

pub(super) struct Row {
    name: String,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    make: Make,
}

impl Row {
    pub(super) fn new(name: String, aliases: Vec<String>, oids: &[&str], make: Make) -> Self {
        let aliases = dedup(&name, aliases);
        let oids = oids
            .iter()
            .map(|dotted| dotted.parse().expect("a valid OID"))
            .collect();
        Self {
            name,
            aliases,
            oids,
            make,
        }
    }
}

// The aliases without the name and without repeats, in any case, as names are found in any case
fn dedup(name: &str, aliases: Vec<String>) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    for alias in aliases {
        if !alias.eq_ignore_ascii_case(name)
            && !kept.iter().any(|known| known.eq_ignore_ascii_case(&alias))
        {
            kept.push(alias);
        }
    }
    kept
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

impl SignerEntry for Row {
    fn create(&self) -> Box<dyn Signer> {
        Box::new(RowSigner {
            make: self.make.clone(),
            inner: None,
        })
    }
}

struct RowSigner {
    make: Make,
    inner: Option<Box<dyn Inner>>,
}

impl RowSigner {
    fn inner(&mut self) -> Result<&mut Box<dyn Inner>, AlgoError> {
        self.inner
            .as_mut()
            .ok_or(AlgoError::new(ErrorKind::NotInitialized))
    }
}

impl tc_signer::Signer for RowSigner {
    type Error = AlgoError;

    fn max_signature_size(&self) -> usize {
        self.inner
            .as_ref()
            .map_or(0, |inner| inner.max_signature_size())
    }

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError> {
        self.inner()?.update(input)
    }

    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.inner()?.generate_signature(output)
    }

    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, AlgoError> {
        self.inner()?.verify_signature(signature)
    }

    fn reset(&mut self) {
        if let Some(inner) = self.inner.as_mut() {
            inner.reset();
        }
    }
}

impl SignerInit<dyn Params> for RowSigner {
    type Error = AlgoError;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        self.inner = None;
        self.inner = Some((self.make)(params)?);
        Ok(())
    }
}

impl Signer for RowSigner {}

// The digest rows a signer takes, each once: every row on but Haraka, which takes inputs of one
// length alone
#[allow(dead_code, reason = "unused by the SM2 rows alone")]
pub(super) fn digests(context: &DefaultAlgoContext) -> Vec<Arc<dyn DigestEntry>> {
    crate::digest::BUILT_IN
        .iter()
        .flat_map(|create| create(context))
        .filter(|digest| !digest.name().starts_with("HARAKA"))
        .map(Arc::from)
        .collect()
}

// The name of a digest in the names of Bouncy Castle's signers: SHA-512/224 is SHA-512(224)
#[allow(dead_code, reason = "unused by the SM2 rows alone")]
pub(super) fn signer_digest_name(digest: &dyn DigestEntry) -> String {
    match digest.name().split_once('/') {
        Some((family, size)) => format!("{family}({size})"),
        None => digest.name().to_string(),
    }
}

// Every name of a digest: its name, its aliases, and its name in the signers' names
#[allow(dead_code, reason = "unused by the SM2 rows alone")]
pub(super) fn digest_names(digest: &dyn DigestEntry) -> Vec<String> {
    let mut names = vec![digest.name().to_string(), signer_digest_name(digest)];
    names.extend(digest.aliases().iter().cloned());
    names
}

// The OIDs of a row out of a table by its name
#[allow(dead_code, reason = "used by the EC rows alone")]
pub(super) fn oids_of<'a>(table: &[(&str, &'a [&'a str])], name: &str) -> &'a [&'a str] {
    table
        .iter()
        .find(|(row, _)| *row == name)
        .map_or(&[], |(_, oids)| oids)
}

// The errors of the digest signers of tc_dsa, DSA-like and GOST
#[cfg(any(
    feature = "dsa",
    all(
        feature = "ecdsa",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    ),
    all(
        feature = "ecnr",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    ),
    all(
        feature = "ecgost3410",
        any(
            feature = "fp-custom",
            feature = "fp-curve",
            feature = "f2m-custom",
            feature = "f2m-curve"
        )
    ),
    feature = "gost3410"
))]
impl<E> Kind for tc_dsa::DsaDigestSignerError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            tc_dsa::DsaDigestSignerError::NotInitialized
            | tc_dsa::DsaDigestSignerError::NotForSigning
            | tc_dsa::DsaDigestSignerError::NotForVerifying => ErrorKind::NotInitialized,
            _ => ErrorKind::DataLength,
        }
    }
}
