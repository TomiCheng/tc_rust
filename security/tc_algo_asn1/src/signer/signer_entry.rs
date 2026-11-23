use tc_asn1_x509::alg::AlgorithmIdentifier;

// A row of signature algorithms: the name tc_algo knows the signer by, and the AlgorithmIdentifier
// a certificate, a CRL or a SignerInfo records for it
pub trait SignerEntry: Send + Sync {
    // The name of the signer in tc_algo
    fn name(&self) -> &str;

    fn aliases(&self) -> &[String] {
        &[]
    }

    // With its parameters, such as the NULL of RSA, as it is written
    fn algorithm(&self) -> &AlgorithmIdentifier;

    // Whether an AlgorithmIdentifier being read is this row's. By the OID alone unless a row says
    // otherwise, so that RSA's NULL may also be absent, as RFC 4055 section 5 asks a reader to
    // accept; a row whose parameters matter, such as RSASSA-PSS, looks at them too
    fn matches(&self, algorithm: &AlgorithmIdentifier) -> bool {
        self.algorithm().algorithm() == algorithm.algorithm()
    }
}
