use std::sync::Arc;

use tc_algo_v2::signer::Signer;
use tc_algo_v2::{Algo, Params};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::X509Error;
use crate::operator::signer::SignerEntry;
use crate::operator::verifier::{Verifier, VerifierFactory};
use crate::operator::{DefaultVerifierCalculator, StreamCalculator};

// BC's Asn1VerifierFactory: a row, a public key, and the AlgorithmIdentifier being verified, which
// may carry parameters the row's own does not. Each calculator gets a new signer
pub(crate) struct DefaultVerifierFactory {
    algo: Arc<dyn Algo>,
    row: Arc<dyn SignerEntry>,
    algorithm: AlgorithmIdentifier,
    public_key: Arc<dyn Params>,
}

impl DefaultVerifierFactory {
    // Initializes a signer once, so that a key the algorithm refuses is reported here
    pub(crate) fn new(
        algo: Arc<dyn Algo>,
        row: Arc<dyn SignerEntry>,
        algorithm: AlgorithmIdentifier,
        public_key: Arc<dyn Params>,
    ) -> Result<Self, X509Error> {
        let factory = Self {
            algo,
            row,
            algorithm,
            public_key,
        };
        factory.signer()?;
        Ok(factory)
    }

    fn signer(&self) -> Result<Box<dyn Signer>, X509Error> {
        let mut signer = self.row.create(self.algo.as_ref())?;
        signer.init(self.public_key.as_ref())?;
        Ok(signer)
    }
}

impl VerifierFactory for DefaultVerifierFactory {
    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }

    fn create_calculator(&self) -> Result<Box<dyn StreamCalculator<Box<dyn Verifier>>>, X509Error> {
        Ok(Box::new(DefaultVerifierCalculator::new(self.signer()?)))
    }
}
