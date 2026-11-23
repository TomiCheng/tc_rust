use tc_algo::Params;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::AlgoAsn1Error;
use crate::signer::Signer;

pub(crate) struct DefaultSigner {
    algorithm: AlgorithmIdentifier,
    inner: Box<dyn tc_algo::signer::Signer>,
}

impl DefaultSigner {
    pub(crate) fn new(
        algorithm: AlgorithmIdentifier,
        inner: Box<dyn tc_algo::signer::Signer>,
    ) -> Self {
        Self { algorithm, inner }
    }
}

impl Signer for DefaultSigner {
    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    fn init(&mut self, key: &dyn Params) -> Result<(), AlgoAsn1Error> {
        Ok(self.inner.init(key)?)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), AlgoAsn1Error> {
        Ok(self.inner.update(data)?)
    }

    fn sign(&mut self) -> Result<Vec<u8>, AlgoAsn1Error> {
        Ok(self.inner.sign()?)
    }

    fn verify(&mut self, signature: &[u8]) -> Result<bool, AlgoAsn1Error> {
        Ok(self.inner.verify_signature(signature)?)
    }
}
