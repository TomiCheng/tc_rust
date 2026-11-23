use std::sync::Arc;

use tc_algo::Algo;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::AlgoAsn1Error;
use crate::mac::{Asn1Mac, DefaultAsn1Mac, MacEntry, MacProvider};

// The rows in the order they are tried, the last registered first, and the algorithms the MACs
// come from
pub(crate) struct DefaultMacProvider {
    algo: Arc<dyn Algo>,
    rows: Vec<Box<dyn MacEntry>>,
}

impl DefaultMacProvider {
    pub(crate) fn new(algo: Arc<dyn Algo>, rows: Vec<Box<dyn MacEntry>>) -> Self {
        Self { algo, rows }
    }

    fn mac(
        &self,
        row: &dyn MacEntry,
        algorithm: AlgorithmIdentifier,
    ) -> Result<Box<dyn Asn1Mac>, AlgoAsn1Error> {
        let inner = self.algo.mac().get_by_name(row.name())?;
        Ok(Box::new(DefaultAsn1Mac::new(algorithm, inner)))
    }
}

impl MacProvider for DefaultMacProvider {
    fn get_by_name(&self, name: &str) -> Result<Box<dyn Asn1Mac>, AlgoAsn1Error> {
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
            .ok_or(AlgoAsn1Error::UnknownMac)?;
        self.mac(row.as_ref(), row.algorithm().clone())
    }

    fn get_by_id(
        &self,
        algorithm: &AlgorithmIdentifier,
    ) -> Result<Box<dyn Asn1Mac>, AlgoAsn1Error> {
        let row = self
            .rows
            .iter()
            .find(|row| row.matches(algorithm))
            .ok_or(AlgoAsn1Error::UnknownMac)?;
        self.mac(row.as_ref(), algorithm.clone())
    }
}
