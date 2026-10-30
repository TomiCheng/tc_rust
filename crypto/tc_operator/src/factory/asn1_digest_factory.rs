use tc_asn1::Asn1Oid;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_digest::TryDigest;
use tc_security::SecurityError;
use tc_security::digest::{self, AnyDigest, DigestEntry};

use crate::calculator::DefaultDigestCalculator;
use crate::{DigestFactory, OperatorError};

pub struct Asn1DigestFactory {
    algorithm: AlgorithmIdentifier,
    entry: &'static DigestEntry,
    digest_size: usize,
}

impl Asn1DigestFactory {
    pub fn new(algorithm: &str) -> Result<Self, OperatorError> {
        Self::from_digest(digest::get_by_name(algorithm)?)
    }

    pub fn with_oid(oid: &Asn1Oid) -> Result<Self, OperatorError> {
        Self::from_digest(digest::get_by_oid(oid)?)
    }

    fn from_digest(digest: AnyDigest) -> Result<Self, OperatorError> {
        let entry = digest.entry();
        let oid = entry.oid().ok_or(SecurityError::UnknownDigest)?;
        Ok(Self {
            algorithm: AlgorithmIdentifier::new(oid.oid()),
            entry,
            digest_size: digest.digest_size(),
        })
    }
}

impl DigestFactory for Asn1DigestFactory {
    type Calculator = DefaultDigestCalculator<AnyDigest>;
    type Error = OperatorError;

    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    fn digest_size(&self) -> usize {
        self.digest_size
    }

    fn create_calculator(&self) -> Result<Self::Calculator, OperatorError> {
        Ok(DefaultDigestCalculator::new(self.entry.create()))
    }
}
