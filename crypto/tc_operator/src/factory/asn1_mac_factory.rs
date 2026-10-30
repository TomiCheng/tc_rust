use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_macs::MacInit;
use tc_security::SecurityError;
use tc_security::mac::{self, AnyMac, MacEntry};
use tc_security::params::AnyParams;

use crate::calculator::DefaultMacCalculator;
use crate::{MacFactory, OperatorError};

pub struct Asn1MacFactory {
    algorithm: AlgorithmIdentifier,
    entry: &'static MacEntry,
    key: AnyParams,
}

impl Asn1MacFactory {
    pub fn new(algorithm: &str, key: AnyParams) -> Result<Self, OperatorError> {
        let entry = mac::get_by_name(algorithm)?;
        let oid = entry.oids().first().ok_or(SecurityError::UnknownMac)?;
        Ok(Self {
            algorithm: AlgorithmIdentifier::new(oid.oid()),
            entry,
            key,
        })
    }

    pub fn with_algorithm(
        algorithm: AlgorithmIdentifier,
        key: AnyParams,
    ) -> Result<Self, OperatorError> {
        let entry = mac::get_by_oid(algorithm.algorithm())?;
        Ok(Self {
            algorithm,
            entry,
            key,
        })
    }
}

impl MacFactory for Asn1MacFactory {
    type Calculator = DefaultMacCalculator<AnyMac>;
    type Error = OperatorError;

    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    fn create_calculator(&self) -> Result<Self::Calculator, OperatorError> {
        let mut mac = self.entry.mac();
        mac.init(&self.key)?;
        Ok(DefaultMacCalculator::new(mac))
    }
}
