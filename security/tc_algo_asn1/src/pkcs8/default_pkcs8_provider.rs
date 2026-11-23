use tc_algo::Params;
use tc_asn1_pkcs::PrivateKeyInfo;

use crate::AlgoAsn1Error;
use crate::pkcs8::{Pkcs8Entry, Pkcs8Provider};

// The rows in the order they are tried, the last registered first
pub(crate) struct DefaultPkcs8Provider {
    rows: Vec<Box<dyn Pkcs8Entry>>,
}

impl DefaultPkcs8Provider {
    pub(crate) fn new(rows: Vec<Box<dyn Pkcs8Entry>>) -> Self {
        Self { rows }
    }
}

impl Pkcs8Provider for DefaultPkcs8Provider {
    fn encode(&self, key: &dyn Params) -> Result<PrivateKeyInfo, AlgoAsn1Error> {
        self.rows
            .iter()
            .find_map(|row| row.encode(key))
            .unwrap_or(Err(AlgoAsn1Error::UnknownPrivateKey))
    }

    fn decode(&self, info: &PrivateKeyInfo) -> Result<Box<dyn Params>, AlgoAsn1Error> {
        self.rows
            .iter()
            .find_map(|row| row.decode(info))
            .unwrap_or(Err(AlgoAsn1Error::UnknownPrivateKey))
    }
}
