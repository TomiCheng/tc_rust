use tc_asn1::NamedOid;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_security::SecurityError;
use tc_security::params::AnyParams;
use tc_security::signer::{self, AnySigner, SignerEntry};
use tc_signer::SignerInit;

use crate::calculator::DefaultSignatureCalculator;
use crate::{OperatorError, SignatureFactory};

const NO_PARAMS: &[&str] = &[
    "1.2.840.10040.4.3",
    "1.3.14.3.2.27",
    "2.16.840.1.101.3.4.3.1",
    "2.16.840.1.101.3.4.3.2",
    "2.16.840.1.101.3.4.3.3",
    "2.16.840.1.101.3.4.3.4",
    "1.2.840.10045.4.1",
    "1.2.840.10045.4.3.1",
    "1.2.840.10045.4.3.2",
    "1.2.840.10045.4.3.3",
    "1.2.840.10045.4.3.4",
    "0.4.0.127.0.7.1.1.4.1.1",
    "0.4.0.127.0.7.1.1.4.1.2",
    "0.4.0.127.0.7.1.1.4.1.3",
    "0.4.0.127.0.7.1.1.4.1.4",
    "0.4.0.127.0.7.1.1.4.1.5",
    "1.2.643.2.2.4",
    "1.2.643.2.2.3",
    "1.2.643.7.1.1.3.2",
    "1.2.643.7.1.1.3.3",
    "1.3.6.1.5.5.7.6.30",
    "1.3.6.1.5.5.7.6.31",
    "1.3.6.1.5.5.7.6.32",
    "1.3.6.1.5.5.7.6.33",
    "2.16.840.1.101.3.4.3.5",
    "2.16.840.1.101.3.4.3.6",
    "2.16.840.1.101.3.4.3.7",
    "2.16.840.1.101.3.4.3.8",
    "2.16.840.1.101.3.4.3.9",
    "2.16.840.1.101.3.4.3.10",
    "2.16.840.1.101.3.4.3.11",
    "2.16.840.1.101.3.4.3.12",
    "0.4.0.127.0.7.1.1.4.1.8",
    "0.4.0.127.0.7.1.1.4.1.9",
    "0.4.0.127.0.7.1.1.4.1.10",
    "0.4.0.127.0.7.1.1.4.1.11",
    "1.2.156.10197.1.503",
    "1.2.156.10197.1.501",
    "1.3.101.112",
    "1.3.101.113",
];

fn sig_alg_id(oid: &NamedOid) -> AlgorithmIdentifier {
    if NO_PARAMS.contains(&oid.dotted()) {
        AlgorithmIdentifier::new(oid.oid())
    } else {
        AlgorithmIdentifier::with_null(oid.oid())
    }
}

pub struct Asn1SignatureFactory {
    algorithm: AlgorithmIdentifier,
    entry: &'static SignerEntry,
    private_key: AnyParams,
}

impl Asn1SignatureFactory {
    pub fn new(algorithm: &str, private_key: AnyParams) -> Result<Self, OperatorError> {
        let entry = signer::get_by_name(algorithm)?;
        let oid = entry.oids().first().ok_or(SecurityError::UnknownSigner)?;
        Ok(Self {
            algorithm: sig_alg_id(oid),
            entry,
            private_key,
        })
    }

    pub fn with_algorithm(
        algorithm: AlgorithmIdentifier,
        private_key: AnyParams,
    ) -> Result<Self, OperatorError> {
        let entry = signer::get_by_oid(algorithm.algorithm())?;
        Ok(Self {
            algorithm,
            entry,
            private_key,
        })
    }
}

impl SignatureFactory for Asn1SignatureFactory {
    type Calculator = DefaultSignatureCalculator<AnySigner>;
    type Error = OperatorError;

    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    fn create_calculator(&self) -> Result<Self::Calculator, OperatorError> {
        let mut signer = self.entry.signer();
        signer.init(&self.private_key)?;
        Ok(DefaultSignatureCalculator::new(signer))
    }
}
