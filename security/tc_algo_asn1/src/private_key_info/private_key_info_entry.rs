use tc_algo::Params;
use tc_asn1_pkcs::PrivateKeyInfo;

use crate::AlgoAsn1Error;

pub trait PrivateKeyInfoEntry: Send + Sync {
    // None when the key is not one this row knows, so that the next row is tried
    fn encode(&self, key: &dyn Params) -> Option<Result<PrivateKeyInfo, AlgoAsn1Error>>;

    // None when the algorithm is not one this row knows, so that the next row is tried
    fn decode(&self, info: &PrivateKeyInfo) -> Option<Result<Box<dyn Params>, AlgoAsn1Error>>;
}
