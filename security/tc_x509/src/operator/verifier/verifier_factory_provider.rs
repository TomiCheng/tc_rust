use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::X509Error;
use crate::operator::verifier::VerifierFactory;

// BC's IVerifierFactoryProvider: a public key waiting for the algorithm, which comes from what is
// verified, such as the signature algorithm of a certificate
pub trait VerifierFactoryProvider: Send + Sync {
    // UnknownSigner when no row knows the algorithm
    fn create_verifier_factory(
        &self,
        algorithm: &AlgorithmIdentifier,
    ) -> Result<Box<dyn VerifierFactory>, X509Error>;
}
