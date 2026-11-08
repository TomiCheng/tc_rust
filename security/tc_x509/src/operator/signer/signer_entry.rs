use tc_algo_v2::Algo;
use tc_algo_v2::signer::Signer;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::X509Error;

// A row of signature algorithms: the AlgorithmIdentifier a certificate records for it, which
// tc_algo_v2 does not know, and the signer of tc_algo_v2 that computes it
pub trait SignerEntry: Send + Sync {
    fn name(&self) -> &str;

    fn aliases(&self) -> &[String] {
        &[]
    }

    // With its parameters, such as the NULL of RSA, as a certificate records it
    fn algorithm(&self) -> &AlgorithmIdentifier;

    // A new signer, not initialized yet
    fn create(&self, algo: &dyn Algo) -> Result<Box<dyn Signer>, X509Error>;
}
