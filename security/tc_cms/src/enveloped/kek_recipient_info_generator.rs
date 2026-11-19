use tc_algo::Algo;
use tc_algo::params::key::KeyOwned;
use tc_asn1::Asn1OctetString;
use tc_asn1_cms::recipient::{KekIdentifier, KekRecipientInfo, RecipientInfo};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_x509::X509Operator;
use tc_zeroize::Zeroizing;

use crate::CmsError;
use crate::algorithms::aes_wrap;
use crate::enveloped::RecipientInfoGenerator;

// BC 的 KekRecipientInfoGenerator：以雙方事先共享的 KEK 包住內容金鑰，AES key wrap（RFC 3394），
// OID 依 KEK 長度。KEK 是 16、24 或 32 bytes，其他長度在 generate 時是 InvalidKey
pub struct KekRecipientInfoGenerator {
    key_identifier: Vec<u8>,
    kek: Zeroizing<Vec<u8>>,
}

impl KekRecipientInfoGenerator {
    pub fn new(key_identifier: &[u8], kek: &[u8]) -> Self {
        Self {
            key_identifier: key_identifier.to_vec(),
            kek: Zeroizing::new(kek.to_vec()),
        }
    }
}

impl RecipientInfoGenerator for KekRecipientInfoGenerator {
    fn generate(
        &self,
        algo: &dyn Algo,
        _x509: &dyn X509Operator,
        content_key: &[u8],
    ) -> Result<RecipientInfo, CmsError> {
        let wrap = aes_wrap(self.kek.len())?;
        let wrapped =
            algo.wrap()
                .wrap_by_oid(&wrap, &KeyOwned::new(self.kek.to_vec()), content_key)?;
        Ok(RecipientInfo::Kek(KekRecipientInfo::new(
            KekIdentifier::new(Asn1OctetString::new(&self.key_identifier)),
            AlgorithmIdentifier::new(wrap),
            Asn1OctetString::new(&wrapped),
        )))
    }
}
