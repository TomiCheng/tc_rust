use std::sync::Arc;

use tc_algo::Algo;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::AlgoAsn1Error;
use crate::cipher::{Asn1Cipher, CipherEntry, CipherProvider, DefaultAsn1Cipher};

// The rows in the order they are tried, the last registered first, and the algorithms the ciphers
// come from
pub(crate) struct DefaultCipherProvider {
    algo: Arc<dyn Algo>,
    rows: Vec<Arc<dyn CipherEntry>>,
}

impl DefaultCipherProvider {
    pub(crate) fn new(algo: Arc<dyn Algo>, rows: Vec<Arc<dyn CipherEntry>>) -> Self {
        Self { algo, rows }
    }

    fn cipher(
        &self,
        row: &Arc<dyn CipherEntry>,
        algorithm: AlgorithmIdentifier,
        by_name: bool,
    ) -> Result<Box<dyn Asn1Cipher>, AlgoAsn1Error> {
        let inner = self.algo.cipher().get_by_name(row.cipher())?;
        Ok(Box::new(DefaultAsn1Cipher::new(
            row.clone(),
            algorithm,
            by_name,
            inner,
        )))
    }
}

impl CipherProvider for DefaultCipherProvider {
    fn get_by_name(&self, name: &str) -> Result<Box<dyn Asn1Cipher>, AlgoAsn1Error> {
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
            .ok_or(AlgoAsn1Error::UnknownCipher)?;
        self.cipher(row, row.generate(), true)
    }

    fn get_by_id(
        &self,
        algorithm: &AlgorithmIdentifier,
    ) -> Result<Box<dyn Asn1Cipher>, AlgoAsn1Error> {
        let row = self
            .rows
            .iter()
            .find(|row| row.matches(algorithm))
            .ok_or(AlgoAsn1Error::UnknownCipher)?;
        self.cipher(row, algorithm.clone(), false)
    }
}
