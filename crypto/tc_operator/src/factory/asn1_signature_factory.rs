use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_security::SecurityError;
use tc_security::params::AnyParams;
use tc_security::signer::{self, AnySigner, SignerEntry};
use tc_signer::SignerInit;

use super::sig_alg_id::sig_alg_id;
use crate::calculator::DefaultSignatureCalculator;
use crate::{OperatorError, SignatureFactory};

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
