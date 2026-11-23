use std::sync::Arc;

use tc_algo::Algo;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::AlgoAsn1Error;
use crate::signer::{DefaultSigner, Signer, SignerEntry, SignerProvider};

// The rows in the order they are tried, the last registered first, and the algorithms the signers
// come from
pub(crate) struct DefaultSignerProvider {
    algo: Arc<dyn Algo>,
    rows: Vec<Box<dyn SignerEntry>>,
}

impl DefaultSignerProvider {
    pub(crate) fn new(algo: Arc<dyn Algo>, rows: Vec<Box<dyn SignerEntry>>) -> Self {
        Self { algo, rows }
    }

    fn signer(
        &self,
        row: &dyn SignerEntry,
        algorithm: AlgorithmIdentifier,
    ) -> Result<Box<dyn Signer>, AlgoAsn1Error> {
        let inner = self.algo.signer().get_by_name(row.name())?;
        Ok(Box::new(DefaultSigner::new(algorithm, inner)))
    }
}

impl SignerProvider for DefaultSignerProvider {
    fn get_by_name(&self, name: &str) -> Result<Box<dyn Signer>, AlgoAsn1Error> {
        let row = self
            .rows
            .iter()
            .find(|row| {
                row.name().eq_ignore_ascii_case(name)
                    || row
                        .aliases()
                        .iter()
                        .any(|alias| alias.eq_ignore_ascii_case(name))
            })
            .ok_or(AlgoAsn1Error::UnknownSigner)?;
        self.signer(row.as_ref(), row.algorithm().clone())
    }

    fn get_by_id(&self, algorithm: &AlgorithmIdentifier) -> Result<Box<dyn Signer>, AlgoAsn1Error> {
        let row = self
            .rows
            .iter()
            .find(|row| row.matches(algorithm))
            .ok_or(AlgoAsn1Error::UnknownSigner)?;
        self.signer(row.as_ref(), algorithm.clone())
    }
}
