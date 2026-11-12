use std::sync::Arc;

use tc_algo::{Algo, Params};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::X509Error;
use crate::operator::signer::{SignatureFactory, SignerEntry};
use crate::operator::{BlockResult, DefaultSignatureCalculator, StreamCalculator};

// BC's Asn1SignatureFactory: a row and a private key. Each calculator gets a new signer, so the
// factory itself does not change and can sign any number of times
pub(crate) struct DefaultSignatureFactory {
    algo: Arc<dyn Algo>,
    row: Arc<dyn SignerEntry>,
    private_key: Arc<dyn Params>,
}

impl DefaultSignatureFactory {
    // Initializes a signer once, so that a key the algorithm refuses is reported here rather than
    // at the first signature
    pub(crate) fn new(
        algo: Arc<dyn Algo>,
        row: Arc<dyn SignerEntry>,
        private_key: Arc<dyn Params>,
    ) -> Result<Self, X509Error> {
        let factory = Self {
            algo,
            row,
            private_key,
        };
        factory.signer()?;
        Ok(factory)
    }

    fn signer(&self) -> Result<Box<dyn tc_algo::signer::Signer>, X509Error> {
        let mut signer = self.row.create(self.algo.as_ref())?;
        signer.init(self.private_key.as_ref())?;
        Ok(signer)
    }
}

impl SignatureFactory for DefaultSignatureFactory {
    fn algorithm(&self) -> &AlgorithmIdentifier {
        self.row.algorithm()
    }

    fn create_calculator(
        &self,
    ) -> Result<Box<dyn StreamCalculator<Box<dyn BlockResult>>>, X509Error> {
        Ok(Box::new(DefaultSignatureCalculator::new(self.signer()?)))
    }
}
