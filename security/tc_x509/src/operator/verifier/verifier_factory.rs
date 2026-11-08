use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::X509Error;
use crate::operator::StreamCalculator;
use crate::operator::verifier::Verifier;

// BC's IVerifierFactory: a public key and the algorithm to verify with
pub trait VerifierFactory: Send + Sync {
    fn algorithm(&self) -> &AlgorithmIdentifier;

    // A calculator for one signature; the signed data is written into it
    fn create_calculator(&self) -> Result<Box<dyn StreamCalculator<Box<dyn Verifier>>>, X509Error>;
}
