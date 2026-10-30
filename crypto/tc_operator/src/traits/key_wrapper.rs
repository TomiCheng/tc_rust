use tc_asn1_x509::alg::AlgorithmIdentifier;

pub trait KeyWrapper {
    type Error: core::error::Error + Send + Sync + 'static;

    fn algorithm(&self) -> &AlgorithmIdentifier;

    fn wrap(&self, key: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
