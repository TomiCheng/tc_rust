use tc_asn1_x509::alg::AlgorithmIdentifier;

// A MAC of tc_algo, by its name there, with the AlgorithmIdentifier it is written as
pub trait MacEntry: Send + Sync {
    // The name tc_algo knows the MAC by
    fn name(&self) -> &str;

    fn aliases(&self) -> &[String] {
        &[]
    }

    // What get_by_name gives
    fn algorithm(&self) -> &AlgorithmIdentifier;

    // Whether an AlgorithmIdentifier being read is this MAC: by default its OID, whatever the
    // parameters, as RFC 4231 asks a reader to accept the NULL present or absent
    fn matches(&self, algorithm: &AlgorithmIdentifier) -> bool {
        self.algorithm().algorithm() == algorithm.algorithm()
    }
}
