use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::VerifierFactory;

pub trait VerifierFactoryProvider {
    type Factory: VerifierFactory;
    type Error: core::error::Error + Send + Sync + 'static;

    fn create_verifier_factory(
        &self,
        algorithm: &AlgorithmIdentifier,
    ) -> Result<Self::Factory, Self::Error>;
}
