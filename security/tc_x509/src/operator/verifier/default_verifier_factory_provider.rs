use std::sync::Arc;

use tc_algo_v2::{Algo, Params};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::X509Error;
use crate::operator::signer::SignerEntry;
use crate::operator::verifier::{DefaultVerifierFactory, VerifierFactory, VerifierFactoryProvider};

// BC's Asn1VerifierFactoryProvider: the public key, and the rows to find the algorithm among
pub(crate) struct DefaultVerifierFactoryProvider {
    algo: Arc<dyn Algo>,
    rows: Vec<Arc<dyn SignerEntry>>,
    public_key: Arc<dyn Params>,
}

impl DefaultVerifierFactoryProvider {
    pub(crate) fn new(
        algo: Arc<dyn Algo>,
        rows: Vec<Arc<dyn SignerEntry>>,
        public_key: Arc<dyn Params>,
    ) -> Self {
        Self {
            algo,
            rows,
            public_key,
        }
    }
}

impl VerifierFactoryProvider for DefaultVerifierFactoryProvider {
    fn create_verifier_factory(
        &self,
        algorithm: &AlgorithmIdentifier,
    ) -> Result<Box<dyn VerifierFactory>, X509Error> {
        let row = self
            .rows
            .iter()
            .find(|row| row.matches(algorithm))
            .ok_or(X509Error::UnknownSigner)?;
        Ok(Box::new(DefaultVerifierFactory::new(
            self.algo.clone(),
            row.clone(),
            algorithm.clone(),
            self.public_key.clone(),
        )?))
    }
}
