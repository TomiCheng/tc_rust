use tc_algo::Params;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

use crate::AlgoAsn1Error;

pub trait SpkiProvider: Send + Sync {
    // The first row that knows the key decides; UnknownPublicKey when none does
    fn encode(&self, key: &dyn Params) -> Result<SubjectPublicKeyInfo, AlgoAsn1Error>;

    // The first row that knows the algorithm decides; UnknownPublicKey when none does
    fn decode(&self, spki: &SubjectPublicKeyInfo) -> Result<Box<dyn Params>, AlgoAsn1Error>;
}
