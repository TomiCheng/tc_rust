use tc_algo::Params;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

use crate::X509Error;

pub trait SpkiEntry: Send + Sync {
    // None when the key is not one this row knows, so that the next row is tried
    fn encode(&self, key: &dyn Params) -> Option<Result<SubjectPublicKeyInfo, X509Error>>;

    // None when the algorithm is not one this row knows, so that the next row is tried
    fn decode(&self, spki: &SubjectPublicKeyInfo) -> Option<Result<Box<dyn Params>, X509Error>>;
}
