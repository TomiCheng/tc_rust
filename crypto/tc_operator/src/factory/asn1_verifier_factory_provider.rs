use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_security::params::AnyParams;

use super::Asn1VerifierFactory;
use crate::{OperatorError, VerifierFactoryProvider};

pub struct Asn1VerifierFactoryProvider {
    public_key: AnyParams,
}

impl Asn1VerifierFactoryProvider {
    pub fn new(public_key: AnyParams) -> Self {
        Self { public_key }
    }
}

impl VerifierFactoryProvider for Asn1VerifierFactoryProvider {
    type Factory = Asn1VerifierFactory;
    type Error = OperatorError;

    fn create_verifier_factory(
        &self,
        algorithm: &AlgorithmIdentifier,
    ) -> Result<Asn1VerifierFactory, OperatorError> {
        Asn1VerifierFactory::with_algorithm(algorithm.clone(), self.public_key.clone())
    }
}
