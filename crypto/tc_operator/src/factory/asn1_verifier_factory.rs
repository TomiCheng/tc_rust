use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_security::SecurityError;
use tc_security::params::AnyParams;
use tc_security::signer::{self, AnySigner, SignerEntry};
use tc_signer::SignerInit;

use super::sig_alg_id::sig_alg_id;
use crate::calculator::DefaultVerifierCalculator;
use crate::{OperatorError, VerifierFactory};

pub struct Asn1VerifierFactory {
    algorithm: AlgorithmIdentifier,
    entry: &'static SignerEntry,
    public_key: AnyParams,
}

impl Asn1VerifierFactory {
    pub fn new(algorithm: &str, public_key: AnyParams) -> Result<Self, OperatorError> {
        let entry = signer::get_by_name(algorithm)?;
        let oid = entry.oids().first().ok_or(SecurityError::UnknownSigner)?;
        Ok(Self {
            algorithm: sig_alg_id(oid),
            entry,
            public_key,
        })
    }

    pub fn with_algorithm(
        algorithm: AlgorithmIdentifier,
        public_key: AnyParams,
    ) -> Result<Self, OperatorError> {
        let entry = signer::get_by_oid(algorithm.algorithm())?;
        Ok(Self {
            algorithm,
            entry,
            public_key,
        })
    }
}

impl VerifierFactory for Asn1VerifierFactory {
    type Calculator = DefaultVerifierCalculator<AnySigner>;
    type Error = OperatorError;

    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    fn create_calculator(&self) -> Result<Self::Calculator, OperatorError> {
        let mut signer = self.entry.signer();
        signer.init(&self.public_key)?;
        Ok(DefaultVerifierCalculator::new(signer))
    }
}
