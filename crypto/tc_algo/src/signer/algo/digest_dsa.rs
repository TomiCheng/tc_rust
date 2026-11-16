use std::sync::Arc;

use rand_core::CryptoRng;
use tc_dsa::RandomDsaKCalculator;

use super::row::{Inner, Row, digest_names, oids_of, signer_digest_name};
use crate::digest::DigestEntry;
use crate::signer::SignerEntry;
use crate::{AlgoError, ErrorKind, Params};

pub(super) type Rand = fn() -> Box<dyn CryptoRng>;

// What a row of a DSA-like scheme over a digest signs with: the digest and the randomness of k
pub(super) struct Spec {
    pub(super) digest: Arc<dyn DigestEntry>,
    pub(super) rand: Rand,
}

// A signer, keyed, when the params are a key of the type it takes; None when they are not
pub(super) type Try = fn(&dyn Params, &Spec) -> Option<Result<Box<dyn Inner>, AlgoError>>;

// k drawn at random, as Bouncy Castle's DSA-like signers draw it
pub(super) fn k(spec: &Spec) -> RandomDsaKCalculator<Box<dyn CryptoRng>> {
    RandomDsaKCalculator::new((spec.rand)())
}

// The row of a digest and a scheme, named SHA-256withECDSA, also SHA256WITHECDSA, SHA-256/ECDSA
// and ECDSAWITHSHA-256, after every name of the digest, with the OIDs of `oids` and the further
// aliases of `extra` for some digests, as ECDSA alone for SHA-1. The first of `tries` that takes the
// params builds the signer
pub(super) fn row(
    digest: &Arc<dyn DigestEntry>,
    scheme: &str,
    tries: &'static [Try],
    oids: &[(&str, &'static [&'static str])],
    extra: &[(&str, &str)],
    rand: Rand,
) -> Box<dyn SignerEntry> {
    let name = format!("{}with{scheme}", signer_digest_name(&**digest));
    let mut aliases: Vec<String> = digest_names(&**digest)
        .iter()
        .flat_map(|digest| {
            [
                format!("{digest}WITH{scheme}"),
                format!("{digest}/{scheme}"),
                format!("{scheme}WITH{digest}"),
            ]
        })
        .collect();
    aliases.extend(
        extra
            .iter()
            .filter(|(of, _)| *of == digest.name())
            .map(|(_, alias)| alias.to_string()),
    );
    let oids = oids_of(oids, &name);
    let spec = Arc::new(Spec {
        digest: digest.clone(),
        rand,
    });
    Box::new(Row::new(
        name,
        aliases,
        oids,
        Arc::new(move |params| {
            tries
                .iter()
                .find_map(|on| on(params, &spec))
                .unwrap_or(Err(AlgoError::new(ErrorKind::InvalidParams)))
        }),
    ))
}
