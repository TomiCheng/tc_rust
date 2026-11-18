use tc_algo::Params;
use tc_asn1_pkcs::PrivateKeyInfo;

use crate::PkcsError;

pub trait PrivateKeyInfoProvider: Send + Sync {
    // The first row that knows the key decides; UnknownPrivateKey when none does
    fn encode(&self, key: &dyn Params) -> Result<PrivateKeyInfo, PkcsError>;

    // The first row that knows the algorithm decides; UnknownPrivateKey when none does
    fn decode(&self, info: &PrivateKeyInfo) -> Result<Box<dyn Params>, PkcsError>;
}
