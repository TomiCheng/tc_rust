use tc_algo::Params;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_signer::SignerInit;

use crate::AlgoAsn1Error;
use crate::signer::Asn1Signer;

pub(crate) struct DefaultAsn1Signer {
    algorithm: AlgorithmIdentifier,
    inner: Box<dyn tc_algo::signer::Signer>,
}

impl DefaultAsn1Signer {
    pub(crate) fn new(
        algorithm: AlgorithmIdentifier,
        inner: Box<dyn tc_algo::signer::Signer>,
    ) -> Self {
        Self { algorithm, inner }
    }
}

impl tc_signer::Signer for DefaultAsn1Signer {
    type Error = AlgoAsn1Error;

    fn max_signature_size(&self) -> usize {
        self.inner.max_signature_size()
    }

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoAsn1Error> {
        Ok(self.inner.update(input)?)
    }

    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, AlgoAsn1Error> {
        Ok(self.inner.generate_signature(output)?)
    }

    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, AlgoAsn1Error> {
        Ok(self.inner.verify_signature(signature)?)
    }

    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl SignerInit<dyn Params> for DefaultAsn1Signer {
    type Error = AlgoAsn1Error;

    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoAsn1Error> {
        Ok(self.inner.init(params)?)
    }
}

impl Asn1Signer for DefaultAsn1Signer {
    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }
}
