use tc_algo_v2::digest::Digest;
use tc_algo_v2::{Algo, AlgoError, ErrorKind};
use tc_asn1::Asn1Oid;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::digest::DigestFactory;

pub struct Asn1DigestFactory<'a> {
    algo: &'a dyn Algo,
    algorithm: AlgorithmIdentifier,
    digest_size: usize,
}

impl<'a> Asn1DigestFactory<'a> {
    // Looks through what the Algo lists, so a name its policy leaves out is UnknownDigest. The
    // algorithm is the row's first OID, and a row without one is UnknownDigest
    pub fn new(algo: &'a dyn Algo, name: &str) -> Result<Self, AlgoError> {
        let digests = algo.digest();
        let row = digests
            .algorithms()
            .find(|row| {
                row.name().eq_ignore_ascii_case(name)
                    || row
                        .aliases()
                        .iter()
                        .any(|alias| alias.eq_ignore_ascii_case(name))
            })
            .ok_or(AlgoError::new(ErrorKind::UnknownDigest))?;
        let oid = row
            .oids()
            .first()
            .ok_or(AlgoError::new(ErrorKind::UnknownDigest))?;
        Self::with_oid(algo, oid)
    }

    pub fn with_oid(algo: &'a dyn Algo, oid: &Asn1Oid) -> Result<Self, AlgoError> {
        let digest_size = algo.digest().get_by_oid(oid)?.digest_size();
        Ok(Self {
            algo,
            algorithm: AlgorithmIdentifier::new(oid.clone()),
            digest_size,
        })
    }
}

impl DigestFactory for Asn1DigestFactory<'_> {
    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    fn digest_size(&self) -> usize {
        self.digest_size
    }

    fn create(&self) -> Result<Box<dyn Digest>, AlgoError> {
        self.algo.digest().get_by_oid(self.algorithm.algorithm())
    }
}
