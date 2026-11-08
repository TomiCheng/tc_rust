use tc_algo_v2::Params;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

use crate::X509Error;
use crate::operator::spki::{SpkiEntry, SpkiProvider};

// The rows in the order they are tried, the last registered first
pub(crate) struct DefaultSpkiProvider {
    rows: Vec<Box<dyn SpkiEntry>>,
}

impl DefaultSpkiProvider {
    pub(crate) fn new(rows: Vec<Box<dyn SpkiEntry>>) -> Self {
        Self { rows }
    }
}

impl SpkiProvider for DefaultSpkiProvider {
    fn encode(&self, key: &dyn Params) -> Result<SubjectPublicKeyInfo, X509Error> {
        self.rows
            .iter()
            .find_map(|row| row.encode(key))
            .unwrap_or(Err(X509Error::UnknownPublicKey))
    }

    fn decode(&self, spki: &SubjectPublicKeyInfo) -> Result<Box<dyn Params>, X509Error> {
        self.rows
            .iter()
            .find_map(|row| row.decode(spki))
            .unwrap_or(Err(X509Error::UnknownPublicKey))
    }
}
