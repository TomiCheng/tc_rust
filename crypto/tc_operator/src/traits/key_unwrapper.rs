use tc_asn1_x509::alg::AlgorithmIdentifier;

pub trait KeyUnwrapper {
    type Error: core::error::Error + Send + Sync + 'static;

    fn algorithm(&self) -> &AlgorithmIdentifier;

    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
