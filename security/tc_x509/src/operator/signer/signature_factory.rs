use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::X509Error;
use crate::operator::{BlockResult, StreamCalculator};

// BC's ISignatureFactory: a private key and the algorithm to sign with
pub trait SignatureFactory: Send + Sync {
    // What a certificate or a CRL records as its signature algorithm
    fn algorithm(&self) -> &AlgorithmIdentifier;

    // A calculator for one signature; the data to sign is written into it
    fn create_calculator(
        &self,
    ) -> Result<Box<dyn StreamCalculator<Box<dyn BlockResult>>>, X509Error>;
}
