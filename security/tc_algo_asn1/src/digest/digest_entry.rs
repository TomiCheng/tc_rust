use tc_asn1::Asn1Oid;
use tc_asn1_x509::alg::AlgorithmIdentifier;

// A digest of tc_algo, by its name there, with the AlgorithmIdentifier it is written as
pub trait DigestEntry: Send + Sync {
    // The name tc_algo knows the digest by
    fn name(&self) -> &str;

    fn aliases(&self) -> &[String] {
        &[]
    }

    // What get_by_name gives
    fn algorithm(&self) -> &AlgorithmIdentifier;

    // Whether an AlgorithmIdentifier being read is this digest: by default its OID, whatever the
    // parameters, as RFC 5754 asks a reader to accept the NULL present or absent
    fn matches(&self, algorithm: &AlgorithmIdentifier) -> bool {
        self.algorithm().algorithm() == algorithm.algorithm()
    }

    // The signature algorithms that hash with this digest, for get_by_signer
    fn signers(&self) -> &[Asn1Oid] {
        &[]
    }
}
