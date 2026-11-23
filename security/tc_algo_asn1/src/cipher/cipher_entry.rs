use tc_algo::Params;
use tc_asn1::Asn1Oid;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::AlgoAsn1Error;

// A cipher of tc_algo with the AlgorithmIdentifier it is written as, whose parameters, such as the
// IV, change with each message
pub trait CipherEntry: Send + Sync {
    // The name get_by_name takes, such as "AES-128-CBC"
    fn name(&self) -> &str;

    fn aliases(&self) -> &[String] {
        &[]
    }

    // The name tc_algo knows the cipher by, such as "AES/CBC/PKCS7PADDING"
    fn cipher(&self) -> &str;

    fn oid(&self) -> &Asn1Oid;

    // Whether an AlgorithmIdentifier being read is this cipher: by default its OID
    fn matches(&self, algorithm: &AlgorithmIdentifier) -> bool {
        self.oid() == algorithm.algorithm()
    }

    // The AlgorithmIdentifier of a new message, with fresh parameters such as a random IV
    fn generate(&self) -> AlgorithmIdentifier;

    // The params tc_algo's cipher takes: the key with the parameters of `algorithm`.
    // InvalidCipherParameters when the parameters are not what the row writes, InvalidKey when the
    // key is not a KeyOwned of the size the row has
    fn params(
        &self,
        algorithm: &AlgorithmIdentifier,
        key: &dyn Params,
    ) -> Result<Box<dyn Params>, AlgoAsn1Error>;
}
