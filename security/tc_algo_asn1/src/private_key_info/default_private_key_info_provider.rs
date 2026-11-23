use tc_algo::Params;
use tc_asn1_pkcs::PrivateKeyInfo;

use crate::AlgoAsn1Error;
use crate::private_key_info::{PrivateKeyInfoEntry, PrivateKeyInfoProvider};

// The rows in the order they are tried, the last registered first
pub(crate) struct DefaultPrivateKeyInfoProvider {
    rows: Vec<Box<dyn PrivateKeyInfoEntry>>,
}

impl DefaultPrivateKeyInfoProvider {
    pub(crate) fn new(rows: Vec<Box<dyn PrivateKeyInfoEntry>>) -> Self {
        Self { rows }
    }
}

impl PrivateKeyInfoProvider for DefaultPrivateKeyInfoProvider {
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
